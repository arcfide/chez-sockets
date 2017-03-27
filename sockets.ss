#!chezscheme
(module (@< =>)
  (import-only (chezscheme))

(define-syntax @< 
  (syntax-rules (=>)
    [(_ (name c ...) => (e ...) b1 b2 ...)
     (for-all identifier? #'(name c ... e ...))
     (module-form name (c ...) (e ...) b1 b2 ...)]
    [(_ (name c ...) b1 b2 ...)
     (value-form name (c ...) b1 b2 ...)]))
(define-syntax (build-value-form x) 
  (syntax-case x ()
    [(_ id (ic ...) body ...)
     (with-syntax ([(oc ...) (datum->syntax #'id (syntax->datum #'(ic ...)))])
       #'(let () (alias ic oc) ... body ...))]))
(define-syntax value-form 
  (syntax-rules ()
    [(_ name (c ...) body ...)
     (define-syntax (name x)
       (syntax-case x ()
         [id (identifier? #'id)
          #'(build-value-form id (c ...) ((... ...) body) ...)]
         [(id . rest)
          #'((build-value-form id (c ...) ((... ...) body) ...) 
             . rest)]))]))
(define-syntax (build-module-form x) 
  (syntax-case x ()
    [(_ id (ic ...) (ie ...) body ...)
     (with-syntax ([(oc ...) (datum->syntax #'id (syntax->datum #'(ic ...)))]
                   [(oe ...) (datum->syntax #'id (syntax->datum #'(ie ...)))])
       #'(module (oe ...)
           (alias ic oc) ...
           (module (ie ...) body ...)
           (alias oe ie) ...))]))
(define-syntax module-form 
  (syntax-rules ()
    [(_ name (c ...) (e ...) body ...)
     (define-syntax (name x)
       (syntax-case x ()
         [id (identifier? #'id)
          #'(build-module-form id (c ...) (e ...)
              ((... ...) body) ...)]))]))
(indirect-export @< 
  module-form value-form build-module-form build-value-form)
)
(@< (Define\x20;Windows\x20;foreign\x20;error\x20;handler ) => (errno errno-message )
(define errno (foreign-procedure "WSAGetLastError" () int))
(define errno-message
  (let ([$format-message 
	 (foreign-procedure __stdcall "FormatMessageA"
			    (unsigned-32 uptr unsigned-32 
			     unsigned-32 uptr unsigned-32 uptr)
			    unsigned-32)]
        [$local-free (foreign-procedure __stdcall "LocalFree" (uptr) void)])
    (lambda (num)
      (let* ([ptr (make-foreign-pointer)]
	     [ret-res ($format-message 
		       (bitwise-xor $format-message-allocate-buffer
				    $format-message-from-system)
		       0 num 0 ptr 0 0)]
	     [res (and (not (zero? ret-res))
		       (get-foreign-string (foreign-pointer-value ptr)))])
	    ($local-free (foreign-pointer-value ptr))
	    (foreign-free ptr)
	    res))))

)

(@< (Build\x20;address\x20;information\x20;hints domain type protocol flags ) 
(make-foreign-address-info
  (fold-left
    (lambda (s v) (fxior s (socket-constant-value v)))
    0 flags)
  (or (and domain (socket-constant-value domain)) 0)
  (or (and type (socket-constant-value type)) 0)
  (or (and protocol (socket-constant-value protocol)) 0)
  0 0 0 0)

)

(@< (Convert\x20;recvfrom\x20;returns\x20;to\x20;scheme\x20;versions n err c buf sock addr addr-len-buf ) 
(if (= n $socket-error)
    (values 
      #f
      (socket-raise/unless 'receive-from-socket 'recvfrom err
        $error-again $error-would-block))
    (values
      (if (< n c)
          (let ([res (make-bytevector n)])
            (bytevector-copy! buf 0 res 0 n)
            res)
          buf)
      (let ([res (foreign->socket-address 
                   (socket-domain sock) 
                   addr addr-len-buf)])
        (foreign-free addr)
        (foreign-free addr-len-buf)
        res)))

)

(@< (Register\x20;pre-defined\x20;socket\x20;domains ) 
(register-socket-domain! socket-domain/unix)
(register-socket-domain! socket-domain/internet)

)

(@< (Socket\x20;constants ) => (address-info/canonical-name address-info/numeric-host address-info/passive socket-domain/unix socket-domain/local socket-domain/internet socket-type/stream socket-type/datagram socket-type/sequence-packet socket-type/raw socket-type/random socket-protocol/auto shutdown-method/read shutdown-method/write shutdown-method/read&write send-to/dont-route send-to/out-of-band receive-from/out-of-band receive-from/peek receive-from/wait-all receive-from/dont-wait )
(define address-info/canonical-name
  (make-address-info-option %ai/canonname))
(define address-info/numeric-host
  (make-address-info-option %ai/numerichost))
(define address-info/passive
  (make-address-info-option %ai/passive))
(define socket-domain/unix
  (make-socket-domain 
   %socket-domain/unix 
   foreign->unix-address 
   size-of/addr-un))
(define socket-domain/local
  (make-socket-domain 
   %socket-domain/local 
   foreign->unix-address 
   size-of/addr-un))
(define socket-domain/internet
  (make-socket-domain 
   %socket-domain/internet 
   foreign->internet-address 
   size-of/addr-in))
(define socket-type/stream
  (make-socket-type %socket-type/stream))
(define socket-type/datagram
  (make-socket-type %socket-type/datagram))
(define socket-type/sequence-packet
  (make-socket-type %socket-type/sequence-packet))
(define socket-type/raw
  (make-socket-type %socket-type/raw))
(define socket-type/random
  (make-socket-type %socket-type/random))
(define socket-protocol/auto (make-socket-protocol 0))
(define shutdown-method/read 
  (make-shutdown-method %shutdown/read))
(define shutdown-method/write 
  (make-shutdown-method %shutdown/write))
(define shutdown-method/read&write
  (make-shutdown-method %shutdown/read&write))
(define send-to/dont-route
  (make-send-to-option %msg/dont-route))
(define send-to/out-of-band 
  (make-send-to-option %msg/out-of-band))
(define receive-from/out-of-band
  (make-receive-from-option %msg/out-of-band))
(define receive-from/peek
  (make-receive-from-option %msg/peek))
(define receive-from/wait-all
  (make-receive-from-option %msg/wait-all))
(define receive-from/dont-wait
  (make-receive-from-option %msg/dont-wait))

)

(@< (Check\x20;\x7C;create-socket\x7C;\x20;arguments domain type protocol ) 
(define who 'create-socket)
(unless (socket-domain? domain)
  (error who "invalid socket domain" domain))
(unless (socket-type? type)
  (error who "invalid socket type" type))
(unless (socket-protocol? protocol)
  (error who "invalid socket protocol" protocol))

)

(@< (Build\x20;socket\x20;and\x20;address\x2C;\x20;then\x20;return sock addr addr-len ret ) 
(values 
  (make-socket ret 
	       (socket-domain sock) 
	       (socket-type sock)
	       (socket-protocol sock))
  (let ([res (foreign->socket-address 
	      (socket-domain sock) addr addr-len)])
    (foreign-free addr) 
    (foreign-free addr-len)
    res))

)

(@< (Foreign\x20;constants ) => ($error-again $error-in-progress $error-would-block $file-set-flag $format-message-allocate-buffer $format-message-from-system $ipproto-ip $ipproto-raw $ipproto-tcp $ipproto-udp $option-non-blocking $socket-error $sol-socket %ai/canonname %ai/numerichost %ai/passive %msg/dont-route %msg/dont-wait %msg/out-of-band %msg/peek %msg/wait-all %shutdown/read %shutdown/read&write %shutdown/write %socket-domain/internet %socket-domain/internet-v6 %socket-domain/local %socket-domain/unix %socket-type/datagram %socket-type/random %socket-type/raw %socket-type/sequence-packet %socket-type/stream %somaxconn af-inet af-unix invalid-socket size-of/addr-in size-of/addr-un size-of/addrinfo size-of/integer size-of/ip size-of/pointer size-of/port size-of/protoent size-of/sa-family size-of/size-t size-of/sockaddr-in size-of/sockaddr-un size-of/socklen-t size-of/wsa-data unix-max-path )
(define-syntax (define-constants x)
  (syntax-case x ()
    [(k head ...)
     (datum->syntax #'k
       `(define-foreign-values ,@(syntax->datum #'(head ...)) int
	  $error-again $error-in-progress $error-would-block #;$file-get-flag
	  $file-set-flag $format-message-allocate-buffer
	  $format-message-from-system $ipproto-ip $ipproto-raw $ipproto-tcp
	  $ipproto-udp $option-non-blocking $socket-error $sol-socket
	  %ai/canonname %ai/numerichost %ai/passive %msg/dont-route %msg/dont-wait
	  %msg/out-of-band %msg/peek %msg/wait-all %shutdown/read
	  %shutdown/read&write %shutdown/write %socket-domain/internet
	  %socket-domain/internet-v6 %socket-domain/local %socket-domain/unix
	  %socket-type/datagram %socket-type/random %socket-type/raw
	  %socket-type/sequence-packet %socket-type/stream %somaxconn af-inet
	  af-unix invalid-socket size-of/addr-in size-of/addr-un size-of/addrinfo
	  size-of/integer size-of/ip size-of/pointer size-of/port size-of/protoent
	  size-of/sa-family size-of/size-t size-of/sockaddr-in size-of/sockaddr-un
	  size-of/socklen-t size-of/wsa-data unix-max-path))]))
(meta-cond
  [(windows?)
   (define-constants "socket-ffi-values.dll" (__cdecl "_get_ffi_value"))]
  [else
   (define-constants "socket-ffi-values.so" "get_ffi_value")])

)

(@< (Foreign\x20;code\x20;initialization ) => ()
(meta-cond
  [(windows?)
   (define $wsa-startup
     (foreign-procedure __stdcall "WSAStartup"
       (unsigned-16 uptr)
       int))
   (define winsock-version (+ (bitwise-arithmetic-shift 2 8) 2))
   (let ([buf (foreign-alloc size-of/wsa-data)])
     ($wsa-startup winsock-version buf)
     (foreign-free buf))]
  [else (void)])

)

(@< (Check\x20;get-address-info\x20;argument\x20;types node service domain type protocol flags ) 
(assert (or (not domain) (socket-domain? domain)))
(assert (or (not type) (socket-type? type)))
(assert (or (not protocol) (socket-protocol? protocol)))
(assert (for-all address-info-option? flags))
(assert (string? node))
(assert 
  (or 
    (string? service) 
    (and 
      (integer? service) 
      (positive? service)
      (< 0 service 65536))))

)

(@< (External\x20;procedure\x20;definitions ) => (string->internet-address string->ipv4 internet-address->string get-address-info create-socket register-socket-domain! socket-domain-db lookup-domain next-protocol-entry get-protocol-by-name get-protocol-by-constant open-protocol-database close-protocol-database bind-socket listen-socket accept-socket connect-socket close-socket shutdown-socket send-to-socket receive-from-socket socket-maximum-connections )
(define (string->internet-address s)
  (let-values ([(ip-string port-string) Split\x20;IPV4\x20;address])
    (let ([ip (and ip-string (string->ipv4 ip-string))]
          [port (and port-string (string->number port-string))])
      (assert (or (not ip) (>= 32 (bitwise-length ip))))
      (assert (or (not port) (< 0 port 65536)))
      (make-internet-address ip port))))
(define (string->ipv4 s)
  (let ([bytes (map string->number (split-string s #\.))])
    (assert (= 4 (length bytes)))
    (fold-left
      (lambda (s x)
        (assert (<= 0 x 255))
        (+ (bitwise-arithmetic-shift s 8) x))
      0
      bytes)))
(define (internet-address->string addr)
  (let ([ip (or (internet-address-ip addr) 0)]
        [port (internet-address-port addr)])
    (assert (or (not port) (< 0 port 65536)))
    (assert (>= 32 (bitwise-length ip)))
    (do ([ip ip (bitwise-arithmetic-shift ip -8)]
         [i 0 (+ i 1)]
         [res '() (cons (mod ip 256) res)])
      [(= 4 i)
       (fold-right
         (lambda (x s)
           (cond 
             [(string? s)
              (string-append (number->string x) "." s)]
             [(number? s)
              (string-append (number->string x) ":" (number->string s))]
             [else (number->string x)]))
          port
          res)])))
(define get-address-info
  (case-lambda
    [(node service) (%get-address-info node service #f #f #f '())]
    [(node service dom type proto . flags)
     (%get-address-info node service dom type proto flags)]))
(define (%get-address-info node service domain type protocol flags)
  Check\x20;get-address-info\x20;argument\x20;types
  (let ([alp (make-foreign-pointer)]
        [hints Build\x20;address\x20;information\x20;hints]
        [service (or (and (string? service) service) 
                     (number->string service 10))])
    (let ([res ($getaddrinfo node service hints alp)])
      (if (zero? res)
          (values Convert\x20;foreign\x20;address\x20;information\x20;list
		  (foreign-address-info-canonical-name
		   (foreign-pointer-value alp)))
          (error 'get-address-info
            "getaddrinfo() failed with code"
            `(code ,res)
            ($gai_strerror res))))))
(define (create-socket domain type protocol)
  Check\x20;\x7C;create-socket\x7C;\x20;arguments
  (call-with-errno 
   (lambda () 
     ($socket (socket-constant-value domain)
	      (socket-constant-value type)
	      (socket-constant-value protocol)))
   (lambda (ret err)
     (if (= ret invalid-socket)
	 (socket-error 'create-socket 'socket err)
	 (let ([sock (make-socket ret domain type protocol)])
	   (set-socket-nonblocking! sock #t)
	   sock)))))
(define socket-domain-db
  (make-parameter '()))
(define (register-socket-domain! domain)
  (assert (socket-domain? domain))
  (let* ([val (socket-constant-value domain)]
         [res (assv val (socket-domain-db))])
    (if res 
        (set-cdr! res domain)
        (socket-domain-db
          (cons (cons val domain) 
                (socket-domain-db))))))
(define (lookup-domain val)
  (let ([res (assv val (socket-domain-db))])
    (and res (cdr res))))
(define (next-protocol-entry)
  (if-windows?
    (unsupported-feature 'next-protocol-entry)
    (foreign->protocol-entry ($getprotoent))))
(define (get-protocol-by-name name)
  (foreign->protocol-entry ($getprotobyname name)))
(define (get-protocol-by-constant proto)
  (foreign->protocol-entry 
    ($getprotobynumber (socket-constant-value proto))))
(define (open-protocol-database keep-alive?)
  (if-windows?
    (unsupported-feature 'open-protocol-database)
    ($setprotoent keep-alive?)))
(define (close-protocol-database)
  (if-windows?
    (unsupported-feature 'close-protocol-database)
    ($endprotoent)))
(define (bind-socket sock addr)
  (let-values ([(foreign-addr foreign-size) 
                (socket-address->foreign addr)])
    (call-with-errno
      (lambda () ($bind (socket-fd sock) foreign-addr foreign-size))
      (lambda (ret err) 
        (foreign-free foreign-addr)
        (when (= ret $socket-error)
          (socket-error 'bind-socket 'bind err))))))
(define (listen-socket sock queue-length)
  (call-with-errno (lambda () ($listen (socket-fd sock) queue-length))
    (lambda (ret err)
      (when (= ret $socket-error)
        (socket-error 'listen-socket 'listen err)))))
(define (accept-socket sock)
  (let ([size (foreign-address-size (socket-domain sock))])
    (let ([addr (foreign-alloc size)]
          [addr-len (make-foreign-size-buffer size)])
      (call-with-errno 
        (lambda () 
	  ((if (socket-nonblocking? sock) $accept $accept-blocking)
	   (socket-fd sock) addr addr-len))
        (lambda (ret err)
          (if (= ret invalid-socket)
	      Return\x20;intelligently\x20;from\x20;non-blocking\x20;errors
	      Build\x20;socket\x20;and\x20;address\x2C;\x20;then\x20;return))))))
(define (connect-socket sock addr)
  (let-values ([(fa fa-len) (socket-address->foreign addr)])
    (call-with-errno 
      (lambda () 
        ((if (socket-nonblocking? sock) 
             $connect 
             $connect-blocking)
         (socket-fd sock) fa fa-len))
      (lambda (ret err)
        (foreign-free fa)
        (or (not (= ret $socket-error))
            (socket-raise/unless 'connect-socket 
                                 'connect 
                                 err
                                 $error-in-progress
				 $error-would-block))))))
(define (close-socket sock)
  (call-with-errno (lambda () ($close (socket-fd sock)))
    (lambda (ret err)
      (when (= ret $socket-error)
        (socket-error 'close-socket 'close err)))))
(define (shutdown-socket sock how)
  (assert (shutdown-method? how))
  (call-with-errno 
    (lambda () 
      ($shutdown (socket-fd sock) (socket-constant-value how)))
    (lambda (ret err)
      (when (= ret $socket-error)
        (socket-error 'shutdown-socket 'shutdown err)))))
(define (send-to-socket sock buf addr . flags)
  (assert (for-all send-to-option? flags))
  (let-values ([(fa fa-len) (socket-address->foreign addr)])
    (call-with-errno 
      (lambda () 
	Convert\x20;datatypes\x20;and\x20;jump\x20;to\x20;the\x20;right\x20;foreign\x20;function)
      (lambda (res err)
        (foreign-free fa)
        (if (= res $socket-error)
            (socket-raise/unless 'send-to-socket 'sendto err
              $error-again $error-would-block)
            res)))))
(define (receive-from-socket sock c . flags)
  (assert (for-all receive-from-option? flags))
  (let ([buf (make-bytevector c)]
        [addr-len (foreign-address-size (socket-domain sock))])
    (let ([addr (foreign-alloc addr-len)]
          [addr-len-buf (make-foreign-size-buffer addr-len)])
      (call-with-errno
        (lambda () 
	  Call\x20;\x5C;$\x7C;recvfrom\x7C;\x20;or\x20;\x5C;$\x7C;recvfrom-blocking\x7C;)
        (lambda (n err)
	  Convert\x20;recvfrom\x20;returns\x20;to\x20;scheme\x20;versions)))))
(define (socket-maximum-connections)
  %somaxconn)

)

(@< (Convert\x20;datatypes\x20;and\x20;jump\x20;to\x20;the\x20;right\x20;foreign\x20;function sock buf flags fa fa-len ) 
((if (socket-nonblocking? sock) $sendto $sendto-blocking)
  (socket-fd sock) buf (bytevector-length buf)
  (fold-left (lambda (s v) (fxior s (socket-constant-value v))) 
	     0 flags)
  fa fa-len)

)

(@< (Call\x20;\x5C;$\x7C;recvfrom\x7C;\x20;or\x20;\x5C;$\x7C;recvfrom-blocking\x7C; sock buf addr addr-len-buf flags c ) 
((if (socket-nonblocking? sock) $recvfrom $recvfrom-blocking)
  (socket-fd sock) buf c 
  (fold-left (lambda (s v) (fxior s (socket-constant-value v))) 
	     0 flags)
  addr addr-len-buf)

)

(@< (Verify\x20;DFV\x20;syntax conv shared-object proc-name type binding ) 
(and (identifier? #'conv)
     (memq (syntax->datum #'conv) '(__cdecl __stdcall __com))
     (string? (syntax->datum #'shared-object))
     (string? (syntax->datum #'proc-name))
     (identifier? #'type)
     (for-all identifier? #'(binding ...)))

)

(@< (Define\x20;POSIX\x20;foreign\x20;error\x20;handler ) => (errno errno-message )
(define errno (foreign-procedure "get_errno" () int))
(define errno-message (foreign-procedure "strerror" (int) string))

)

(@< (Define\x20;\x7C;get-ffi-value\x7C; %get-ffi-value ) => (get-ffi-value )
(define-syntax (get-ffi-value x)
  (syntax-case x ()
    [(k name) (identifier? #'name)
     #`'#,(datum->syntax #'k 
            (%get-ffi-value 
	     (symbol->string (syntax->datum #'name))))]))

)

(@< (Foreign\x20;functions ) => (call-with-errno errno-message $getaddrinfo $gai_strerror $socket $getprotobyname $getprotobynumber $bind $listen $accept $connect $close $shutdown $sendto $recvfrom $getsockopt $setsockopt $fcntl $getprotoent $setprotoent $endprotoent $accept-blocking $connect-blocking $sendto-blocking $recvfrom-blocking make-foreign-unix-address foreign-unix-address-path make-foreign-ipv4-address foreign-ipv4-address-ip foreign-ipv4-address-port host->network/u16 host->network/u32 network->host/u16 network->host/u32 make-foreign-pointer foreign-pointer-value make-foreign-address-info foreign-address-info-canonical-name foreign-address-info-next foreign-address-info-domain foreign-address-info-type foreign-address-info-protocol foreign-address-info-address foreign-address-info-address-length foreign-protocol-entry-name foreign-protocol-entry-aliases foreign-protocol-entry-protocol get-foreign-string make-foreign-size-buffer foreign-size-buffer-value %set-blocking )
(meta-cond
  [(windows?) Define\x20;Windows\x20;foreign\x20;error\x20;handler]
  [else Define\x20;POSIX\x20;foreign\x20;error\x20;handler])
(define (call-with-errno thunk receiver)
  (call-with-values
   (lambda () (critical-section (let ([v (thunk)]) (values v (errno)))))
   receiver))
(define-ffi $socket "socket" (fixnum fixnum fixnum) fixnum)
(define-ffi $getaddrinfo "getaddrinfo" (string string uptr uptr) int)
(define-ffi $getprotobyname "getprotobyname" (string) uptr)
(define-ffi $getprotobynumber "getprotobynumber" (fixnum) uptr)
(define-ffi $bind "bind" (fixnum uptr fixnum) fixnum)
(define-ffi $listen "listen" (fixnum fixnum) fixnum)
(define-ffi $accept "accept" (fixnum uptr uptr) fixnum)
(define-ffi $connect "connect" (fixnum uptr fixnum) fixnum)
(define-ffi $shutdown "shutdown" (fixnum fixnum) fixnum)
(define-ffi $sendto "sendto" (fixnum u8* fixnum fixnum uptr fixnum) fixnum)
(define-ffi $recvfrom "recvfrom" (fixnum u8* fixnum fixnum uptr uptr) fixnum)
(define-ffi $getsockopt "getsockopt" (int int int uptr uptr) int)
(define-ffi $setsockopt "setsockopt" (int int int uptr int) int)
(meta-cond
  [(windows?) 
   (define $gai_strerror errno-message)
   (define-ffi $close "closesocket" (unsigned) int)
   (define-ffi $fcntl "ioctlsocket" (unsigned unsigned unsigned) int)]
  [else 
   (define $gai_strerror (foreign-procedure "gai_strerror" (int) string))
   (define-ffi $close "close" (int) int)
   (define-ffi $fcntl "fcntl" (int int long) int)])
(meta-cond
  [(windows?)
   (define ($getprotoent) (unsupported-feature '$getprotoent))
   (define ($setprotoent) (unsupported-feature '$setprotoent))
   (define ($endprotoent) (unsupported-feature '$endprotoent))]
  [else
   (define $getprotoent (foreign-procedure "getprotoent" () uptr))
   (define $setprotoent (foreign-procedure "setprotoent" (boolean) void))
   (define $endprotoent (foreign-procedure "endprotoent" () void))])
(meta-cond
  [(threaded?)
   (define $accept-blocking
     (foreign-procedure "accept_block" (fixnum uptr uptr) int))
   (define $connect-blocking
     (foreign-procedure "connect_block" (fixnum uptr fixnum) int))
   (define $sendto-blocking
     (foreign-procedure "sendto_block" 
			(fixnum u8* fixnum fixnum uptr fixnum) 
			int))
   (define $recvfrom-blocking
     (foreign-procedure "recvfrom_block" 
			(fixnum u8* fixnum fixnum uptr uptr)
			int))]
  [else 
   (define $accept-blocking
     (foreign-procedure "accept" (fixnum uptr uptr) int))
   (define $connect-blocking
     (foreign-procedure "connect" (fixnum uptr fixnum) int))
   (define $sendto-blocking
     (foreign-procedure "sendto" (fixnum u8* fixnum fixnum uptr fixnum) int))
   (define $recvfrom-blocking
     (foreign-procedure "recvfrom" (fixnum u8* fixnum fixnum uptr uptr) int))])
(define make-foreign-unix-address 
  (let ([$strcpy (foreign-procedure "strcpy" (uptr string) void)])
    (lambda (path)
      (let ([res (foreign-alloc size-of/sockaddr-un)]
            [path-len (string-length path)])
        (assert (< path-len unix-max-path))
        (foreign-set! 'unsigned-short res 0 af-unix)
        ($strcpy (+ res size-of/sa-family) path)
        res))))
(define foreign-unix-address-path
  (let ([$strncpy (foreign-procedure "strncpy" (u8* uptr fixnum) string)])
    (lambda (addr)
      ($strncpy (make-bytevector unix-max-path 0) 
                (+ addr size-of/sa-family)
                unix-max-path))))
(define (make-foreign-ipv4-address port ip)
  (let ([res (foreign-alloc size-of/sockaddr-in)])
    (foreign-set! 'unsigned-short res 0 af-inet)
    (foreign-set! 'unsigned-16 
                  res 
                  (foreign-sizeof 'unsigned-short)
                  (host->network/u16 port))
    (foreign-set! 'unsigned-32
                  res
                  (+ (foreign-sizeof 'unsigned-short)
                     (foreign-sizeof 'unsigned-16))
                  (host->network/u32 ip))
    res))
(define (foreign-ipv4-address-ip addr)
  (network->host/u32
    (foreign-ref 'unsigned-32 
                 addr
                 (+ (foreign-sizeof 'unsigned-short) 
                    (foreign-sizeof 'unsigned-16)))))

(define (foreign-ipv4-address-port addr)
  (network->host/u16
    (foreign-ref 'unsigned-16
                 addr
                 (foreign-sizeof 'unsigned-short))))
(define host->network/u16
  (if (eq? (native-endianness) (endianness big))
      (lambda (x) x)
      (lambda (x)
        (let ([buf (make-bytevector 2)])
          (bytevector-u16-set! buf 0 x (endianness big))
          (bytevector-u16-ref buf 0 (native-endianness))))))

(define host->network/u32
  (if (eq? (native-endianness) (endianness big))
      (lambda (x) x)
      (lambda (x)
        (let ([buf (make-bytevector 4)])
          (bytevector-u32-set! buf 0 x (endianness big))
          (bytevector-u32-ref buf 0 (native-endianness))))))
          
(define network->host/u32 host->network/u32)
(define network->host/u16 host->network/u16)
(define (make-foreign-pointer)
  (foreign-alloc (foreign-sizeof 'void*)))

(define (foreign-pointer-value x)
  (foreign-ref 'void* x 0))
  
(define family-offset (foreign-sizeof 'int))
(define type-offset (+ family-offset (foreign-sizeof 'int)))
(define proto-offset (+ type-offset (foreign-sizeof 'int)))
(define addrlen-offset (+ proto-offset (foreign-sizeof 'int)))
(define addr-offset (+ addrlen-offset (foreign-sizeof 'unsigned-long)))
(define name-offset (+ addr-offset (foreign-sizeof 'void*)))
(define next-offset (+ name-offset (foreign-sizeof 'void*)))
  
(define (make-foreign-address-info 
          flags family type proto addrlen addr name next)
  (let ([res (foreign-alloc size-of/addrinfo)])
    (foreign-set! 'int res 0 flags)
    (foreign-set! 'int res family-offset family)
    (foreign-set! 'int res type-offset type)
    (foreign-set! 'int res proto-offset proto)
    (foreign-set! 'unsigned-long res addrlen-offset addrlen)
    (foreign-set! 'void* res addr-offset addr)
    (foreign-set! 'void* res name-offset name)
    (foreign-set! 'void* res next-offset next)
    res))

(define (foreign-address-info-canonical-name addrinfo)
  (let ([ptr (foreign-ref 'void* addrinfo name-offset)])
    (if (zero? ptr) #f (get-foreign-string ptr))))

(define (foreign-address-info-domain addrinfo)
  (foreign-ref 'int addrinfo family-offset))
(define (foreign-address-info-type addrinfo)
  (foreign-ref 'int addrinfo type-offset))
(define (foreign-address-info-protocol addrinfo)
  (foreign-ref 'int addrinfo proto-offset))
(define (foreign-address-info-address addrinfo)
  (foreign-ref 'void* addrinfo addr-offset))
(define (foreign-address-info-address-length addrinfo)
  (foreign-ref 'unsigned-long addrinfo addrlen-offset))
(define (foreign-address-info-next addrinfo)
  (foreign-ref 'void* addrinfo next-offset))
(define (foreign-protocol-entry-name x)
  (get-foreign-string (foreign-pointer-value x)))

(define (foreign-protocol-entry-aliases x)
  (do ([ptr (foreign-ref 'void* x (foreign-sizeof 'void*))
            (+ ptr (foreign-sizeof 'void*))]
       [res '()  (cons (get-foreign-string (foreign-pointer-value ptr))
                       res)])
      [(zero? (foreign-pointer-value ptr)) (reverse res)]))

(define (foreign-protocol-entry-protocol x)
  (foreign-ref 'int x (* 2 (foreign-sizeof 'void*))))
(define get-foreign-string
  (let ([$strlen (foreign-procedure "strlen" (uptr) fixnum)]
        [$strcpy (foreign-procedure "strcpy" (u8* uptr) string)])
    (lambda (x)
      (let* ([len ($strlen x)]
             [buf (make-bytevector (1+ len))])
        ($strcpy buf x)))))
(define (make-foreign-size-buffer size)
  (let ([res (foreign-alloc (foreign-sizeof 'unsigned-long))])
    (foreign-set! 'unsigned-long res 0 size)
    res))

(define (foreign-size-buffer-value buf)
  (foreign-ref 'unsigned-long buf 0))
(meta-cond
  [(windows?)
   (define (%set-blocking fd yes?)
     (let ([buf (make-foreign-size-buffer (if yes? 0 1))])
       ($fcntl fd $file-set-flag buf)))]
  [else
    (define (%set-blocking fd yes?)
      ($fcntl fd $file-set-flag (if yes? 0 $option-non-blocking)))])

)

(@< (Return\x20;intelligently\x20;from\x20;non-blocking\x20;errors err ) 
(values 
  #f 
  (socket-raise/unless 'accept-socket 'accept err
		       $error-again $error-would-block))

)

(@< (Convert\x20;foreign\x20;address\x20;information\x20;list alp ) 
(define (get-address-info-entry alp)
  (let ([dom (lookup-domain (foreign-address-info-domain alp))])
    (if dom
        (make-address-info
          dom
          (make-socket-type (foreign-address-info-type alp))
          (make-socket-protocol (foreign-address-info-protocol alp))
          (foreign->socket-address 
            dom
            (foreign-address-info-address alp)
            (foreign-address-info-address-length alp)))
        #f)))
(do ([ptr (foreign-pointer-value alp) (foreign-address-info-next ptr)]
     [res '() 
       (let ([entry (get-address-info-entry ptr)])
         (if entry (cons entry res) res))])
  [(zero? ptr) (reverse res)])

)

(@< (Datatype\x20;definitions ) => (make-socket socket? socket socket-nonblocking? socket-nonblocking?-set! socket-fd socket-domain socket-type socket-protocol socket-option? make-socket-option socket-option socket-option-foreign-size socket-option-foreign-maker socket-option-foreign-converter socket-option-id socket-option-level define-socket-option-type make-tcp-option make-udp-option make-raw-option make-ip-option tcp-option? udp-option? raw-option? ip-option? define-socket-option-type tcp-option udp-option raw-option ip-option socket-address? socket-address socket-address-converter socket-address->foreign foreign->socket-address unix-address? make-unix-address unix-address-path unix-address unix-address->foreign foreign->unix-address internet-address internet-address? make-internet-address internet-address-ip internet-address-port internet-address->foreign foreign->internet-address socket-constant make-socket-constant socket-constant? socket-constant-value make-address-info address-info? address-info address-info-domain address-info-type address-info-protocol address-info-address make-address-info-option address-info-option address-info-option? %socket-domain make-socket-domain socket-domain? socket-domain-extractor foreign-address-size %socket-type make-socket-type socket-type? make-socket-protocol socket-protocol? make-protocol-entry protocol-entry? protocol-entry protocol-entry-name protocol-entry-aliases protocol-entry-value foreign->protocol-entry shutdown-method make-shutdown-method shutdown-method? send-to-option make-send-to-option send-to-option? receive-from-option make-receive-from-option receive-from-option? get-socket-option set-socket-option! set-socket-nonblocking! &socket make-socket-condition socket-condition? socket-condition-who socket-condition-syscall socket-condition-type socket-condition-message )
(define-record-type socket
  (fields fd domain type protocol (mutable nonblocking?))
  (protocol
    (lambda (n)
      (lambda (fd domain type protocol)
        (n fd domain type protocol #f)))))
(define-record-type socket-option
  (fields level id foreign-size foreign-maker foreign-converter)
  (protocol 
    (lambda (p) 
      (case-lambda
        [(id size maker converter)  
         (p $sol-socket id size maker converter)] 
        [(id size maker converter level) 
         (p level id size maker converter)]))))
(define-syntax define-socket-option-type
  (syntax-rules ()
    [(_ name level)
     (define-record-type name (parent socket-option)
       (protocol 
         (lambda (n) 
           (lambda (id size maker converter) 
             ((n id size maker converter level))))))]))
(define-socket-option-type tcp-option $ipproto-tcp)
(define-socket-option-type udp-option $ipproto-udp)
(define-socket-option-type raw-option $ipproto-raw)
(define-socket-option-type ip-option $ipproto-ip)
(define-record-type socket-address (fields converter))
(define (socket-address->foreign sock-addr)
  ((socket-address-converter sock-addr) sock-addr))
(define (foreign->socket-address domain addr addr-len)
  ((socket-domain-extractor domain) addr addr-len))
(define-record-type unix-address
  (parent socket-address)
  (protocol
    (lambda (n) (lambda (path) ((n unix-address->foreign) path))))
  (fields path))
(define (unix-address->foreign addr) 
  (if-windows? 
    (unsupported-feature 'unix-sockets)
    (values (make-foreign-unix-address (unix-address-path addr))
	    size-of/sockaddr-un)))
(define (foreign->unix-address addr addr-len)
  (if-windows?
    (unsupported-feature 'unix-sockets)
    (make-unix-address (foreign-unix-address-path addr))))
(define-record-type internet-address 
  (parent socket-address)
  (protocol 
    (lambda (n) 
      (lambda (i p) ((n internet-address->foreign) i p))))
  (fields ip port))
(define (internet-address->foreign addr)
  (values 
    (make-foreign-ipv4-address
      (internet-address-port addr)
      (internet-address-ip addr))
    size-of/sockaddr-in))
(define (foreign->internet-address addr addr-len)
  (make-internet-address
    (foreign-ipv4-address-ip addr)
    (foreign-ipv4-address-port addr)))
(define-record-type socket-constant (fields (immutable value)))
(define-record-type address-info (fields domain type protocol address))
(define-record-type address-info-option (parent socket-constant))
(define-record-type (%socket-domain make-socket-domain socket-domain?)
  (parent socket-constant)
  (fields 
    (immutable extractor socket-domain-extractor)
    (immutable addr-size foreign-address-size)))
(define-record-type (%socket-type make-socket-type socket-type?)
  (parent socket-constant))
(define-record-type 
  (%socket-protocol make-socket-protocol socket-protocol?)
  (parent socket-constant))
(define-record-type protocol-entry (fields name aliases value))
(define (foreign->protocol-entry x)
  (make-protocol-entry
    (foreign-protocol-entry-name x)
    (foreign-protocol-entry-aliases x)
    (foreign-protocol-entry-protocol x)))
(define-record-type shutdown-method (parent socket-constant))
(define-record-type send-to-option (parent socket-constant))
(define-record-type receive-from-option (parent socket-constant))
(define (get-socket-option sock opt)
  (let ([len (socket-option-foreign-size opt)])
    (let ([fbuf (foreign-alloc len)] 
          [flen (make-foreign-size-buffer len)])
      (call-with-errno
        (lambda () 
          ($getsockopt (socket-fd sock) 
            (socket-option-level opt)
            (socket-option-id opt)
            fbuf flen))
        (lambda (ret err)
          (if (= ret $socket-error)
              (begin (foreign-free fbuf) (foreign-free flen)
                (socket-error 'get-socket-option 'getsockopt err))
              (let ([res ((socket-option-foreign-converter opt)
                          fbuf
                          (foreign-size-buffer-value flen))])
                (foreign-free fbuf)
                (foreign-free flen)
                res)))))))
(define (set-socket-option! sock opt val)
  (let-values ([(buf buf-len) ((socket-option-foreign-maker opt) val)])
    (call-with-errno
      (lambda ()
        ($setsockopt
          (socket-fd sock)
          (socket-option-level opt)
          (socket-option-id opt)
          buf buf-len))
      (lambda (ret err)
        (foreign-free buf)
        (when (= ret $socket-error)
          (socket-error 'set-socket-option! 'setsockopt err))))))
(define (set-socket-nonblocking! sock val)
  (call-with-errno 
    (lambda () 
      (%set-blocking (socket-fd sock) (not val)))
    (lambda (ret err)
      (when (= ret $socket-error)
        (socket-error 'set-socket-nonblocking! 'fcntl err))
      (socket-nonblocking?-set! sock val))))
(define-condition-type &socket &condition make-socket-condition socket-condition?
  (who socket-condition-who)
  (syscall socket-condition-syscall)
  (type socket-condition-type)
  (msg socket-condition-message))

)

(@< (Internal\x20;procedure\x20;definitions ) => (split-string socket-error socket-raise/unless )
(define (split-string s c)
  (define (debuf buf) (list->string (reverse buf)))
  (define (split lst res buf)
    (cond
      [(null? lst) (reverse (cons (debuf buf) res))]
      [(char=? c (car lst)) (split (cdr lst) (cons (debuf buf) res) '())]
      [else (split (cdr lst) res (cons (car lst) buf))]))
  (if (fxzero? (string-length s))
      '()
      (split (string->list s) '() '())))
(define (socket-error who call errval)
  (raise (make-socket-condition who call errval (errno-message errval))))
(define (socket-raise/unless who call errval . vals)
  (let ([cnd (make-socket-condition who call errval (errno-message errval))])
    (if (memv (socket-condition-type cnd) vals) cnd (raise cnd))))

)

(@< (Split\x20;IPV4\x20;address s ) 
(let ([val (split-string s #\:)])
  (if (pair? val)
      (values
        (car val)
        (and (pair? (cdr val)) (cadr val)))
      (values #f #f)))

)

(@< (Foreign\x20;code\x20;utilities ) => (windows? if-windows? unsupported-feature resolve define-foreign-values define-bindings define-ffi )
(meta define (windows?) (memq (machine-type) '(i3nt ti3nt)))
(define-syntax (if-windows? x)
  (syntax-case x ()
    [(_ c a) (if (windows?) #'c #'a)]))
(define (unsupported-feature feature)
  (error feature "this feature is not supported on this platform"))
(define-syntax (on-machine x)
  (syntax-case x (else)
    [(_) #'(begin)]
    [(_ (else exp)) #'(begin (define-syntax (t x) exp) (t))]
    [(_ ((type ...) exp) rest ...)
     (if (memq (machine-type) (syntax->datum #'(type ...)))
         #'(begin (define-syntax (t x) exp) (t))
         #'(on-machine rest ...))]))
(define-syntax fake-define
  (syntax-rules ()
    [(_ exp ...) (define dummy (begin exp ... (void)))]))
(on-machine
  [(i3nt ti3nt a6nt ta6nt) #'(fake-define (load-shared-object "crtdll.dll"))]
  [(i3le ti3le a6le ta6le) #'(fake-define (load-shared-object "libc.so.6"))]
  [(i3osx ti3osx a6osx ta6osx)
   #'(fake-define (load-shared-object "libc.dylib"))]
  [else #'(fake-define (load-shared-object "libc.so"))])
(on-machine
  [(i3nt ti3nt a6nt ta6nt)
   (begin (load-shared-object "socket-ffi-values.dll") #'(fake-define))]
  [(i3osx ti3osx ta6osx a6osx)
   (begin (load-shared-object "socket-ffi-values.dylib") #'(fake-define))]
  [else (begin (load-shared-object "socket-ffi-values.so") #'(fake-define))])
(on-machine
  [(ti3nt ta6nt) #'(fake-define (load-shared-object "sockets-stub.dll"))]
  [(ti3osx ta6osx) #'(fake-define (load-shared-object "sockets-stub.dylib"))]
  [else
    (if (threaded?)
        #'(fake-define (load-shared-object "sockets-stub.so"))
        #'(fake-define))])
(meta define (resolve name)
  (let loop ([dirs (source-directories)])
    (cond
      [(not (pair? dirs)) name]
      [(let ([path (format "~a~a~a" (car dirs) (directory-separator) name)])
         (and (file-exists? path) path))]
      [else (loop (cdr dirs))])))
(define-syntax define-foreign-values
  (syntax-rules ()
    [(_ shared-object (conv proc-name) type binding ...)
     Verify\x20;DFV\x20;syntax
     (begin 
       (meta define %get-ffi-value
         (begin 
           (load-shared-object (resolve shared-object))
           (foreign-procedure conv proc-name (string) type)))
       Define\x20;\x7C;get-ffi-value\x7C;
       (define-bindings get-ffi-value binding ...))]
    [(_ shared-object proc-name type binding ...)
     (with-syntax ([conv #'__cdecl])
       Verify\x20;DFV\x20;syntax)
     (begin 
       (meta define %get-ffi-value
         (begin 
           (load-shared-object (resolve shared-object))
           (foreign-procedure proc-name (string) type)))
       Define\x20;\x7C;get-ffi-value\x7C;
       (define-bindings get-ffi-value binding ...))]))
(define-syntax define-bindings
  (syntax-rules ()
    [(_ get) (begin)]
    [(_ get binding) (define binding (get binding))]
    [(_ get binding rest ...)
     (begin (define binding (get binding))
       (define-bindings get rest ...))]))
(define-syntax define-ffi
  (syntax-rules ()
    [(_ name ffiname in out)
     (define name
       (meta-cond
	[(windows?) (foreign-procedure __stdcall ffiname in out)]
	[else (foreign-procedure ffiname in out)]))]))

)

Foreign\x20;code\x20;utilities
Foreign\x20;constants
Foreign\x20;functions
Foreign\x20;code\x20;initialization
Datatype\x20;definitions
Socket\x20;constants
Internal\x20;procedure\x20;definitions
External\x20;procedure\x20;definitions
Register\x20;pre-defined\x20;socket\x20;domains
