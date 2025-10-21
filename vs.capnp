@0x910cda10d7c9c52c;

interface VisaService {
  connect   @0 (req :VSConnectRequest) -> (resp :VSConnectResponse);
}

interface VSGate {
  challenge    @0 () -> (challenge: Challenge);
  authenticate @1 (cresp: ChallengeResponse) -> (res :VSConnection);
}

interface VSHandle {
  registerVss       @0 (addr: SockAddr) -> (res :Result); 

  authorizeConnect  @1 (req :ConnectRequest) -> (resp :ConnectResponse);
  reauthorize       @2 (req :ReauthRequest) -> (resp :ConnectResponse);
  notifyDisconnect  @3 (req :DisconnectNotice) -> (res :Result);

  visaRequest       @4 (req :VisaRequest) -> (resp :VisaResponse);

  ping              @5 () -> (res :Result);
}

struct Result {
  union {
    ok @0 :Void;
    error @1 :Error;
  }
}


# ---------------------------------------------------
# Authentication
# ---------------------------------------------------


enum ChallengeAlg {
  rsaSha256Pkcs1v15 @0;
}

struct Challenge {
  alg     @0 :ChallengeAlg;
  bytes   @1 :Data;
}

struct ChallengeResponse {
  challenge @0 :Data;   # copied from request
  timestamp @1 :UInt64;
  bytes     @2 :Data; # response (ie, signature) based on challenge type.
}

struct ReauthRequest {
  zprAddr  @0 :IpAddr; 
  blobs    @1 :List(Blob);
}

struct Blob {
  union {
    ss @0 :ZPRSelfSignedBlob;
    ac @1 :AuthCodeBlob;
  }
}

struct ZPRSelfSignedBlob {
  alg        @0 :ChallengeAlg;
  challenge  @1 :Data;   
  cn         @2 :Text;
  timestamp  @3 :UInt64;
  signature  @4 :Data; 
}

struct AuthCodeBlob {
  asaAddr   @0 :IpAddr;
  code      @1 :Text;
  pkce      @2 :Text;
  clientId  @3 :Text;
}


# ---------------------------------------------------
# Connections
# ---------------------------------------------------

enum VSConnT {
  reset @0;     # new connect, no state
  reconnect @1; # reconnect, has state
}

enum ParamT {
  string @0;
  u64    @1;
  ipv4   @2;
  ipv6   @3;
}

struct Param {
  ptype @0 :ParamT;
  name  @1 :Text;
  value @2 :Data;
} 

struct VSConnectRequest {
  cn     @0 :Text;
  ctype  @1 :VSConnT;
  params @2 :List(Param); # none are required (yet)
}

struct VSConnection {
  union {
    handle @0 :VSHandle;
    error  @1 :Error;
  }
}

struct VSConnectResponse {
  union {
    gate   @0 :VSGate;   
    error  @1 :Error;
  }
}

struct ConnectRequest {
  blobs          @0 :List(Blob);
  claims         @1 :List(Claim);
  substrateAddr  @2 :IpAddr;
  dockInterface  @3 :UInt8;  # zero means 'unspecified/default'
}


struct Claim {
  key   @0 :Text;
  value @1 :Text;
}


# TODO - Support for node connections.
struct ConnectResponse {
  union {
    success   @0 :Connection;
    error     @1 :Error;
  }
}

struct DisconnectNotice {
  zprAddr     @0 :IpAddr; 
  reasonCode  @1 :DisconnectReason;
}


enum DisconnectReason {
  remoteDisconnect @0;
  timeout          @1;
  linkError        @2;
  nodeShutdown     @3;
  admin            @4;
}


struct Connection {
  zprAddr     @0 :IpAddr;
  authExpires @1 :UInt64;
}


# ---------------------------------------------------
# Visas
# ---------------------------------------------------

struct PacketDesc {
  sourceAddr @0 :IpAddr; # zpr address
  destAddr   @1 :IpAddr; # zpr address
  protocol   @2 :UInt8;
  sourcePort @3 :UInt16; # or ICMP type
  destPort   @4 :UInt16; # or ICMP code
  commType   @5 :CommType;
}

enum CommType {
  bidirectional  @0;
  unidirectional @1;
  rerequest      @2;
}

struct VisaRequest {
  packet      @0 :PacketDesc;
  previousId  @1 :UInt64;  # zero if none
}

struct VisaResponse {
  union {
    allow   @0 :Visa;
    deny    @1 :VisaDenyCode;
    error   @2 :Error;
  }
}

enum VisaDenyCode {
  noReason        @0;
  noMatch         @1;
  denied          @2; # matched a NEVER ALLOW...
  sourceNotFound  @3;
  destNotFound    @4;
  sourceAuthError @5;
  destAuthError   @6;
  quotaExceeded   @7;
}
  

struct Visa {
  issuerId    @0 :UInt64;  # unique in a running ZPRnet
  expiration  @1 :UInt64;
  sourceAddr  @2 :IpAddr;
  destAddr    @3 :IpAddr;
  dockPep     @4 :DockPep;
  constraints @5 :List(Constraint);
  sessionKey  @6 :KeySet;
}

struct DockPep {
  union {
    tcpudp @0 :DockPepTcpUdp;
    icmp   @1 :DockPepIcmp;
  }
}

# TODO: Not including prototype "icmpAllow" until we need it.
struct DockPepTcpUdp {
  sourcePort @0 :UInt16;
  destPort   @1 :UInt16;
  enpoint    @2 :EndpointT;  # is visa designed for server dock or client dock
}

# TODO: Not including the "stateful" icmp from prototype until we need it.
struct DockPepIcmp {
  icmpTypeCode    @0 :UInt16; # type | code
}

struct KeySet {
  format     @0 :KeyFormat;
  ingressKey @1 :Data;
  egressKey  @2 :Data;
}

# TODO: Not yet implemented
struct Constraint {}    
  
enum KeyFormat {
  zprKF01 @0; # TBD
}

enum EndpointT {
  any    @0;
  server @1;
  client @2;
}


# ---------------------------------------------------
# Errors
# ---------------------------------------------------


struct Error {
  code    @0 :ErrorCode;
  message @1 :Text; 
  retryIn @2 :UInt32; # seconds until retry is acceptable, 0 if unknown
}

# These are mostly guesses.
enum ErrorCode {
  internal               @0;
  authRequired           @1;  # means node should re-auth.
  invalidOperation       @2;
  outOfSync              @3;
  notFound               @4;
  invalidSignature       @5;
  quotaExceeded          @6;
  temporarilyUnavailable @7;
}


# ---------------------------------------------------
# Misc
# ---------------------------------------------------

struct IpAddr {
  union {
    v4 @0 :Data;
    v6 @1 :Data;
  }
}

struct SockAddr {
  addr @0 :IpAddr;
  port @1 :UInt16;
}


##
## VSSAPI
##

interface VisaSupportService {
  connect @0 (req: VSSConnectRequest) -> (vss :VSSHandle, error :Error);
}

# TODO: Information about policy and topology 
interface VSSHandle {
  pushVisaOp            @0 (ops :List(VisaOp)) -> (ack :Ack);
  revokeAuthentication  @1 (addrs :List(IpAddr)) -> (ack :Ack);
  setServices           @2 (version :UInt64, svcs :List(ServiceDescriptor)) -> (res :Result);
  ping                  @3 () -> (res :Result);
}

struct VSSConnectRequest { # reserved for future
  hello @0 :Void;
}


# ---------------------------------------------------
# Services
# ---------------------------------------------------

struct ServiceDescriptor {
  stype      @0 :ServiceT;
  serviceId  @1 :Text;
  serviceUri @2 :Text;
  zprAddr    @3 :IpAddr;
}

enum ServiceT {
  actorAuthentication @0;
}


# ---------------------------------------------------
# Pushes 
# ---------------------------------------------------

struct VisaOp {
  union {
    grant        @0 :Visa;
    revokeVisaId @1 :UInt64;
  }
}

struct Ack {
  ok         @0 :Bool;   # if any pushed item is processed successfully, this is TRUE.
  error      @1 :Error;  # if not all items are processed successfully, this holds an error.
  processed  @2 :UInt32; # 0 <= processed < len(pushed-items) 
}


