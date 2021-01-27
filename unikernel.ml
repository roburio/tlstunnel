(* (c) 2020 Hannes Mehnert, all rights reserved *)

(* left to do:
   - haproxy1 support (PROXY TCP4|6 SOURCEIP DESTIP SRCPORT DESTPORT\r\n) at the beginning of the TCP connection to the backend
   - NG: apart from SNI allow other ports to be redirected (no proxy)
*)

open Lwt.Infix

module Main (C : Mirage_console.S) (R : Mirage_random.S) (T : Mirage_time.S) (Pclock : Mirage_clock.PCLOCK) (Block : Mirage_block.S) (Public : Mirage_stack.V4V6) (Private : Mirage_stack.V4V6) (Management : Mirage_stack.V4V6) = struct
  let snis =
    Monitoring_experiments.counter_metrics ~f:(fun x -> x) "tlstunnel"

  let access kind =
    let s = ref (0, 0) in
    let open Metrics in
    let doc = "connection statistics" in
    let data () =
      Data.v [
        int "active" (fst !s) ;
        int "total" (snd !s) ;
      ] in
    let tags = Tags.string "kind" in
    let src = Src.v ~doc ~tags:Tags.[ tags ] ~data "connections" in
    (fun action ->
       (match action with
        | `Open -> s := (succ (fst !s), succ (snd !s))
        | `Close -> s := (pred (fst !s), snd !s));
       Metrics.add src (fun x -> x kind) (fun d -> d ()))

  let frontend_access = access "frontend"
  let tls_access = access "tls"
  let config_access = access "config"
  let http_access = access "http"
  let backend_access = access "backend"

  module FS = Filesystem.Make(Pclock)(Block)

  module M = Map.Make(String)

  type config = {
    mutable superblock : FS.superblock ;
    mutable sni : (Ipaddr.t * int) M.t ;
  }

  let read_configuration block =
    FS.read_data block >>= function
    | Error `Bad_checksum ->
      (FS.init block >>= function
        | Ok superblock -> Lwt.return { superblock ; sni = M.empty }
        | Error `Msg e ->
          Logs.err (fun m -> m "error initializing the block device %s" e);
          Lwt.fail_with "initializing block device")
    | Error `Msg msg ->
      Logs.err (fun m -> m "error reading block device %s" msg);
      Lwt.fail_with "reading block device"
    | Error (#FS.decode_err as e) ->
      Logs.err (fun m -> m "error reading block device %a" FS.pp_decode_err e);
      Lwt.fail_with "reading block device"
    | Ok (superblock, data) ->
      Logs.info (fun m -> m "read from %a (counter %u) %u bytes data"
                    (Ptime.pp_rfc3339 ()) superblock.FS.timestamp
                    superblock.FS.super_counter
                    superblock.FS.data_length);
      let config = { superblock ; sni = M.empty } in
      if Cstruct.len data > 0 then begin
        let sni = Configuration.decode_data data in
        config.sni <- sni;
      end;
      Logs.info (fun m -> m "SNI map has %d entries" (M.cardinal config.sni));
      Lwt.return config

  let write_configuration block config =
    let open Lwt_result.Infix in
    let data = Configuration.encode_data config.sni in
    FS.write_data block config.superblock data >|= fun superblock ->
    config.superblock <- superblock

  let handle_config block config cmd =
    match cmd with
    | Configuration.Add (sni, host, port) ->
      begin
        let snis = Configuration.add_sni config.sni (sni, host, port) in
        config.sni <- snis;
        write_configuration block config >|= function
        | Ok () -> Configuration.Result (0, sni ^ " was successfully added")
        | Error `Msg m -> Configuration.Result (1, "error " ^ m ^ " adding " ^ sni)
      end
    | Configuration.Remove sni ->
      begin
        let snis = Configuration.remove_sni config.sni sni in
        config.sni <- snis;
        write_configuration block config >|= function
        | Ok () -> Configuration.Result (0, sni ^ " was successfully removed")
        | Error `Msg m -> Configuration.Result (1, "error " ^ m ^ " removing " ^ sni)
      end
    | Configuration.List ->
      let snis =
        M.fold (fun sni (host, port) acc -> (sni, host, port) :: acc)
          config.sni []
      in
      Lwt.return (Configuration.Snis snis)
    | _ ->
      Lwt.return (Configuration.Result (1, "unexpected"))

  let handle_command block config data =
    (match Configuration.cmd_of_cs data with
     | Ok cmd -> handle_config block config cmd
     | Error `Msg err -> Lwt.return (Configuration.Result (2, err))) >|= fun reply ->
    Configuration.cmd_to_cs reply

  module H = Mirage_crypto.Hash.SHA256

  let auth key data =
    if Cstruct.len data > H.digest_size then
      let auth, data = Cstruct.split data H.digest_size in
      if Cstruct.equal (H.hmac ~key data) auth then
        Some data
      else
        None
    else
      None

  let config_cmd block config key data =
    match auth key data with
    | None -> Lwt.return (Configuration.cmd_to_cs (Configuration.Result (3, "authentication failure")))
    | Some data -> handle_command block config data

  let config_change block config key tcp =
    config_access `Open;
    (Private.TCP.read tcp >>= function
      | Error e ->
        Logs.err (fun m -> m "config TCP read error %a" Private.TCP.pp_error e);
        Lwt.return_unit
      | Ok `Eof ->
        Logs.warn (fun m -> m "config TCP read eof");
        Lwt.return_unit
      | Ok `Data buf ->
        let buf' = Cstruct.shift buf 8 in
        let l = Cstruct.BE.get_uint64 buf 0 in
        if Cstruct.len buf' = Int64.to_int l then
          config_cmd block config key buf' >>= fun res ->
          let size = Cstruct.create 8 in
          Cstruct.BE.set_uint64 size 0 (Int64.of_int (Cstruct.len res));
          Private.TCP.write tcp (Cstruct.append size res) >|= function
          | Ok () -> ()
          | Error e ->
            Logs.warn (fun m -> m "config TCP write error %a" Private.TCP.pp_write_error e)
        else begin
          Logs.warn (fun m -> m "truncated config message");
          Lwt.return_unit
        end)
    >>= fun () ->
    config_access `Close;
    Private.TCP.close tcp

  module TLS = Tls_mirage.Make(Public.TCP)

  let extract_location content =
    (* we assume a HTTP request in here, and want to reply with a moved
       permanently (301) carrying a location header of the form
       Location: https://<host>/<url>
       So we decode the incoming read data for
       (a) "HTTP method" "URL" (anything else)
       (b) "Host:" <data> header *)
    match Astring.String.cuts ~sep:"\r\n" content with
    | request :: headers ->
      begin
        match
          Astring.String.cuts ~sep:" " request,
          List.find_opt (fun x ->
              Astring.String.is_prefix ~affix:"host:"
                (Astring.String.Ascii.lowercase x))
            headers
        with
        | _method :: url :: _, Some host ->
          begin match Astring.String.cut ~sep:":" host with
            | Some (_, host) ->
              let loc = ["https://" ; Astring.String.trim host ; url ] in
              Some (String.concat "" loc)
            | None ->
              Logs.warn (fun m -> m "no name in host header %S" host);
              None
          end
        | _ ->
          Logs.warn (fun m -> m "no url or host header found in %S" content);
          None
      end
    | [] ->
      Logs.warn (fun m -> m "no http header found in %S" content);
      None

  let redirect tcp =
    http_access `Open;
    Public.TCP.read tcp >>= fun data ->
    let reply = match data with
      | Error e ->
        Logs.err (fun m -> m "TCP error %a" Public.TCP.pp_error e);
        None
      | Ok `Eof ->
        Logs.err (fun m -> m "TCP eof");
        None
      | Ok `Data data ->
        (* this is slighly brittle since it only uses the first bytes read() *)
        extract_location (Cstruct.to_string data)
    in
    (match reply with
     | None -> Lwt.return_unit
     | Some data ->
       let reply =
         let status = "HTTP/1.1 301 Moved permanently"
         and location = "Location: " ^ data
         and content_len = "Content-Length: 0"
         and server = "Server: OCaml TLStunnel"
         in
         String.concat "\r\n" [ status ; location ; content_len ; server ; "" ; "" ]
       in
       Public.TCP.write tcp (Cstruct.of_string reply) >|= function
       | Ok () -> ()
       | Error e ->
         Logs.err (fun m -> m "error %a sending redirect" Public.TCP.pp_write_error e))
    >>= fun () ->
    http_access `Close;
    Public.TCP.close tcp

  let close tls tcp =
    tls_access `Close;
    frontend_access `Close;
    backend_access `Close;
    Private.TCP.close tcp >>= fun () ->
    TLS.close tls

  let rec read_tls_write_tcp tls tcp =
    TLS.read tls >>= function
    | Error e ->
      Logs.err (fun m -> m "TLS read error %a" TLS.pp_error e);
      close tls tcp
    | Ok `Eof -> close tls tcp
    | Ok `Data buf ->
      Private.TCP.write tcp buf >>= function
      | Error e ->
        Logs.err (fun m -> m "TCP write error %a" Private.TCP.pp_write_error e);
        close tls tcp
      | Ok () ->
        read_tls_write_tcp tls tcp

  let rec read_tcp_write_tls tcp tls =
    Private.TCP.read tcp >>= function
    | Error e ->
      Logs.err (fun m -> m "TCP read error %a" Private.TCP.pp_error e);
      close tls tcp
    | Ok `Eof -> close tls tcp
    | Ok `Data buf ->
      TLS.write tls buf >>= function
      | Error e ->
        Logs.err (fun m -> m "TLS write error %a" TLS.pp_write_error e);
        close tls tcp
      | Ok () ->
        read_tcp_write_tls tcp tls

  let tls_accept priv config tls_config tcp_flow =
    frontend_access `Open;
    (* TODO this should timeout the TLS handshake with a reasonable timer *)
    TLS.server_of_flow tls_config tcp_flow >>= function
    | Error e ->
      Logs.warn (fun m -> m "TLS error %a" TLS.pp_write_error e);
      frontend_access `Close;
      Public.TCP.close tcp_flow
    | Ok tls_flow ->
      tls_access `Open;
      let close () =
        tls_access `Close;
        frontend_access `Close;
        TLS.close tls_flow
      in
      match TLS.epoch tls_flow with
      | Ok epoch ->
        begin
          let default () = M.find_opt "default" config.sni in
          match
            match epoch.Tls.Core.own_name with
            | None ->
              Metrics.add snis (fun x -> x) (fun d -> d "no sni");
              default ()
            | Some sni ->
              match M.find_opt sni config.sni with
              | None ->
                Logs.warn (fun m -> m "server name %s not configured" sni);
                default ()
              | Some (host, port) ->
                Metrics.add snis (fun x -> x) (fun d -> d sni);
                Some (host, port)
          with
          | None -> close ()
          | Some (host, port) ->
            Private.TCP.create_connection priv (host, port) >>= function
            | Error e ->
              Logs.err (fun m -> m "error %a connecting to backend"
                           Private.TCP.pp_error e);
              close ()
            | Ok tcp_flow ->
              backend_access `Open;
              Lwt.join [
                read_tls_write_tcp tls_flow tcp_flow ;
                read_tcp_write_tls tcp_flow tls_flow
              ]
        end
      | Error () ->
        Logs.warn (fun m -> m "unexpected error retrieving the TLS session");
        close ()

  module D = Dns_certify_mirage.Make(R)(Pclock)(T)(Public)
  module Monitoring = Monitoring_experiments.Make(T)(Management)
  module Syslog = Logs_syslog_mirage.Udp(C)(Pclock)(Management)

  let start c _ () () block pub priv management =
    let hostname = Key_gen.name () in
    (match Key_gen.syslog () with
     | None -> Logs.warn (fun m -> m "no syslog specified, dumping on stdout")
     | Some ip -> Logs.set_reporter (Syslog.create c management ip ~hostname ()));
    (match Key_gen.monitor () with
     | None -> Logs.warn (fun m -> m "no monitor specified, not outputting statistics")
     | Some ip -> Monitoring.create ~hostname ip management);
    read_configuration block >>= fun config ->
    Private.listen_tcp priv ~port:(Key_gen.configuration_port ())
      (config_change block config (Cstruct.of_string (Key_gen.key ())));
    let domains = Key_gen.domains ()
    and key_seed = Key_gen.key_seed ()
    and dns_key = Key_gen.dns_key ()
    and dns_server = Key_gen.dns_server ()
    in
    Public.listen_tcp pub ~port:80 redirect;
    let rec retrieve_certs () =
      Lwt_list.fold_left_s (fun acc domain ->
          let key_seed = domain ^ ":" ^ key_seed in
          D.retrieve_certificate pub ~dns_key
            ~hostname:Domain_name.(host_exn (of_string_exn domain))
            ~additional_hostnames:[ Domain_name.of_string_exn ("*." ^ domain) ]
            ~key_seed dns_server 53 >>= function
          | Error `Msg err -> Lwt.fail_with err
          | Ok certificates -> Lwt.return (certificates :: acc))
        [] domains >>= fun cert_chains ->
      (match List.rev cert_chains with
       | [] -> Lwt.fail_with "empty certificate chains"
       | a :: _ -> Lwt.return a) >>= fun first ->
      let certificates = `Multiple_default (first, cert_chains) in
      let tls_config = Tls.Config.server ~certificates () in
      let priv_tcp = Private.tcp priv in
      let port = Key_gen.frontend_port () in
      Public.listen_tcp pub ~port (tls_accept priv_tcp config tls_config);
      let now = Ptime.v (Pclock.now_d_ps ()) in
      let seven_days_before_expire =
        let next_expire =
          let expiring =
            List.map snd
              (List.map X509.Certificate.validity
                 (List.map (function (s::_, _) -> s | _ -> assert false)
                      cert_chains))
          in
          let diffs = List.map (fun exp -> Ptime.diff exp now) expiring in
          let closest_span = List.hd (List.sort Ptime.Span.compare diffs) in
          fst (Ptime.Span.to_d_ps closest_span)
        in
        max (Duration.of_hour 1) (Duration.of_day (next_expire - 7))
      in
      T.sleep_ns seven_days_before_expire >>= fun () ->
      retrieve_certs ()
    in
    retrieve_certs ()
end
