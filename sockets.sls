(library (arcfide sockets)
  (export make-socket socket? socket-fd socket-domain socket-type socket-protocol
	  socket-option? make-socket-option socket-option
	  define-socket-option-type
	  make-tcp-option make-udp-option make-raw-option make-ip-option
	  tcp-option? udp-option? raw-option? ip-option? 
	  socket-address? socket-address
	  unix-address? make-unix-address unix-address-path
	  internet-address? make-internet-address internet-address-ip
	  internet-address-port string->internet-address
	  internet-address->string string->ipv4
	  make-address-info address-info? address-info-domain
	  address-info-type address-info-protocol address-info-address
	  get-address-info
	  address-info/canonical-name address-info/numeric-host
	  address-info/passive
	  create-socket make-socket-domain make-socket-type
	  socket-domain/unix socket-domain/local 
	  socket-domain/internet socket-type/stream socket-type/datagram
	  socket-type/sequence-packet socket-type/raw socket-type/random 
	  register-socket-domain!
	  make-socket-protocol socket-protocol?
	  protocol-entry-name protocol-entry-aliases protocol-entry-value
	  socket-protocol/auto next-protocol-entry
	  get-protocol-by-name get-protocol-by-constant
	  open-protocol-database close-protocol-database
	  bind-socket listen-socket accept-socket connect-socket
	  close-socket shutdown-socket shutdown-method? make-shutdown-method
	  shutdown-method/read shutdown-method/write shutdown-method/read&write
	  send-to-socket send-to/dont-route send-to/out-of-band
	  make-send-to-option
	  receive-from-socket receive-from/out-of-band receive-from/peek 
	  receive-from/wait-all receive-from/dont-wait
	  make-receive-from-option
	  socket-maximum-connections
	  get-socket-option set-socket-option! set-socket-nonblocking!
	  socket-nonblocking?
	  make-socket-condition socket-condition?
	  socket-condition-who socket-condition-syscall socket-condition-type
	  socket-condition-message socket-error socket-raise/unless)
  (import (chezscheme))
  (include "sockets.ss"))
