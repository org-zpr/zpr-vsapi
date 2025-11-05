@0x910cda10d7c9c52c;

# There are two APIs between the nodes and visa services. The Visa Service Api
# (VSAPI) and the Visa Service Support API (VSSAPI). These are RPC client/server
# type APIs defined in Cap'n Proto IDL. For the VSAPI the client is a node and the
# server is the Visa Service; vice versa for the VSSAPI.
#
# This document describes the initial, minimal functionality of these two APIs. It
# is expected that the APIs will develop over time.
#
# Both APIs:
#
#   * Use TCP with TLS, optionally checking cert signatures. (TODO: OK to not
#     check sigs? We want privacy here, not authentication.)
#
#   * Timestamp values are sent as unix timestamps (seconds since epoch) in UInt64
#     data types.
#
#   * IP Addresses are assumed to be 16-byte IPv6 addresses unless otherwise
#     noted.
#
#   * Support a healthcheck call ("ping") that is intended to be used to catch
#     connectivity errors faster than TCP timeout.
#
# ZPL policy controls access to both APIs:
#
#   * Access to the VS API is controlled using node CN values and RSA keys
#     embedded in the policy.
#
#   * Access to the VSSAPI on each node is controlled by ZPL policy inserted by
#     the ZPL compiler.
#
# State Model
#
# The visa server maintains the set of non-expired visas installed on each node.
# For each node it also keeps track of pending visas which need to be pushed, and
# pending revocations (either for visas or authentications). Finally, the visa
# service keeps track of all actors connected to each node. The visa service is
# the source of truth as it is where decisions are made about what communications
# are allowed. The visa service is designed to maintain state across restarts, the
# node is not -- when a node restarts it has no installed visas and no connected
# adapters.
#
# The visa service does rely on nodes to expire their installed visas so it is
# important that the clocks of the nodes and visa service are fairly closely
# synchronized.
#
#
#
#
# ----------------------------------------------------------------------------- 
# VSAPI 
# ----------------------------------------------------------------------------- 
#
# Setup:
#
#   * Visa Service has a self-signed certificate with the CN and SAN set to
#     "vs.zpr".
#
#   * The Node's CN value is set in policy as the 'endpoint.zpr.adapter.cn'
#     attribute on the node provider.
#
#   * The first ZPR node has no way to authenticate prior to connecting to the
#     Visa Service, so there is an authentication step as part of connecting to
#     the VS API.
#
#
# General API design:
#
# The Cap'n Proto RPC system we are using lends itself to an OO style of API
# design. So we have three objects that allow a node to go from unauthenticated
# client to holder of a valid Visa Service handle.
#
#   * First the node opens a connection to a VisaService object which offers a
#     single "connect" function.
#
#   * The connect function returns a VSGate object which has a "challenge"
#     function that returns a challenge to the node. The node responds to the
#     challenge using the "authenticate" function, also on the VSGate object.
#
#   * If the challenge response is accepted by the Visa Service then a VSHandle
#     object is returned to the node. The VSHandle object has functions for all
#     the operations available to the node.
#
#
# Authentication:
#
#   * Each node is pre-configured with an RSA keypair and a CS value (a string).
#     The ZPR policy maps node CN values to RSA public keys. During the
#     authentication step the visa service checks that the node indicated by its
#     CN value has the correct private key.
#
#   * The challenge handed to the node is an opaque byte buffer. The visa service
#     does not reuse challenge data or reconnect tokens.
#
#   * To produce the challenge-response result the node performs:
#     - RSA_SHA256_SIGN_PKCS_1.5(CONCAT(TIMESTAMP, CN, CHALLENGE)), where:
#       - TIMESTAMP is unix seconds since the epoch (u64, big endian)
#       - CN is the nodes UTF-8 encoded CN value (not null terminated)
#       - CHALLENGE is the challenge byte buffer from the visa service
#
#   * The Visa Service checks the challenge-response by computing the same SHA256
#     hash that the node did, and then verifying the signature.
#
#
# Actor Connect and Disconnect:
#
# The node is responsible for facilitating the authentication of client adapters
# and other nodes. The Visa Service performs the actual authentication, but it
# does so in response to messages sent by nodes through the VSHandle API object.
#
# The connect request includes:
#
#   * Claims made by the connecting actor. Must include the
#     'endpoint.zpr.adapter.cn' claim. May include other claims like a ZPR
#     address.
#
#   * A list of blobs. These are authentication tokens either self signed or
#     returned from an authentication service.
#
#   * The substrate address (source address) being used by the connecting actor.
#
#   * If the dock has multiple substrate interfaces, the interface number being
#     used as the dock.
#
# The VSHandle provides a notify_disconnect function that the node must call when
# an adapter or node disconnects (including when the node itself is
# disconnecting).
#
#
# Re-Authorization:
#
#   * All authorizations have expirations. Before the authorization for an actor
#     expires the node may use the "reauthorize" function to submit updated
#     credentials for the actor.
#
#
# Visa Requests:
#
# Requesting a visa involves the node sending a description of the packet to the
# Visa Service which then checks the communicating actors and the communication
# against policy. If a visa is granted it is returned.
#
#
# State:
#
# When a node connects to a visa service the node can indicate if it has state or
# if it is a new connection with no state. The visa service uses this to determine
# how to handle pre-existing node state in the visa service (if any). The visa
# service may decide that a node is irreparably out of sync and in that case if a
# node attempts to connect with the "reconnect" flag the visa service will return
# an "invalidState" error, causing the node to clear its state (and disconnect any
# adapters) and try a clean connect.
#
# After a reconnect the visa service will tear down any existing connection it may
# have to a node's VSSAPI, and will wait for a call to the registerVss function
# before opening a new VSS connection back to the node.
#
# The node is responsible for telling the visa service about connected adapters
# through the "authorizeConnect" call. While a node is disconnected from a visa
# service no new connections can be made (since they require authentication from
# the visa service), but connections may be terminated. The node must notify the
# visa service of all disconnects, queueing them up if the visa service is
# disconnected.
#
# When a node is performing a clean shutdown, it should call the
# "notifyDisconnect" function for all its adapters, and for itself.
#
# While the visa service is disconnected from a node, new visas may be created
# that need to be pushed to the node (similarly, visas may need to be revoked).
# These push operations are queued up to be performed once the node re-joins the
# visa service.
#
# When the node and visa service come back together, and both the node and visa
# service agree that they have maintained state, they are synchronized in a
# best-effort way as follows:
#
#   * Node first calls "registerVss" to bring up the VSSAPI.
#
#   * Visa service will push the current services list which overwrites whatever
#     the node had in memory.
#
#   * Visa Service performs any pending pushes for visa grants.
#
#   * Visa Service performs any pending pushes for visa revocations.
#
#   * Visa Service performs any pending pushes for authentication revocations.
#
#   * Node sends any pending disconnects.
#
#
# Impact of synchronization failures:
#
#   1. Node has visas installed that the visa service has forgotten.  
#
#      This happens in a benign way all the time: due to visa expiration clock
#      skew. A node holding a visa that has been revoked should be an impossible
#      situation if visa service and node are correctly implemented.
#
#   2. Visa service thinks node has visas that it no longer has.  
#
#      The node will simply re-request visas it needs.
#
#   3. Node has connected adapters that visa service does not know about. 
#
#      These adapters will never get visas granted since visa service doesn't know
#      they exist. Node can detect this by checking the visa deny reason code and
#      then re-authenticate the adapter.
#
#   4. Visa service thinks node has adapters that it does not have. 
#
#      Visa service could end up pushing a visa to the node for an unknown
#      adapter. Node should log the error and not install the visa.
#
#
# If a node crashes it will lose all its adapter connections and stored visas.
# When it reconnects to the visa service it will specify to the visa service that
# it is a connection "reset". The visa service will then know the node has lost
# all its adapters and visas and will clear the node state on its side (ie, by
# removing the actors from the connected table, removing the related visas, etc).
#
# If the node is gone for an extended period (configured in the visa service) the
# visa service may purge all its state related to the node. If after that a node
# attempts to connect as a "reconnect", the visa service will return an
# "invalidOperation" error and the node should purge its state (and connections)
# and reconnect as a "reset" connection.
#
#
#
# ----------------------------------------------------------------------------- 
# VSSAPI
# ----------------------------------------------------------------------------- 
#
# Setup:
#
#   * The VSSAPI is hosted by a node on its ZPR address at either the default port
#     or a port of its choosing. The address of the node's VSSAPI is sent to the
#     Visa Service over the VSAPI using the "registerVss" call.
#
#   * The Visa Service response to the register-vss call will usually include one
#     or more visas. These are any visas that may have been created when the node
#     connected plus a visa allowing the VS to communicate with the node on the
#     VSS port.  If the node is unable to process the visas in the response it
#     should disconnect from the Visa Service and try connecting again.
#
#   * Once a node registers its VSSAPI address through the VSAPI, the Visa Service
#     will attempt to open a connection to the VSSAPI.
#
#   * Since policy rules control access to the VSSAPI, and a node connects to only
#     one Visa Service at a time, there is no authentication step required when
#     the Visa Service connects to the VSS.
#
#
# The VSSAPI is used by the visa service to push information to a node.
#
#   * Visa grants or revocations.
#
#   * Authentication Revocations - Sent as a list of actor ZPR addresses.
#
#   * Services list - Pushed to the node when visa service first connects to the
#     VSSAPI, and asynchronously afterwards if the services list changes.
#
# This API will grow as we determine how best to communicate important policy
# information (like topology) to the nodes.
#
#
# State:
#
# The Visa Service keeps track of the VSSAPI address for each connected node. The
# node can update this at any time by calling the "registerVss" function on the
# VSAPI.
#
# If the Visa Service loses connectivity with a node's VSSAPI, but it is still
# connected with the node over the VSAPI, it will retry the VSS connection. If the
# VSS connection cannot be reestablished after some time the node will be
# disconnected.
#
# When a node connects to the Visa Service the visa service will reset any state
# it has concerning the VSSAPI address for that node. It is up to the node to call
# "registerVss" after connecting (or reconnecting). If a newly connected node
# fails to call "registerVss" within some (configurable) amount of time, this is
# considered a protocol error and the node will be disconnected.
#
# When the Visa Service opens a connection to the VSSAPI, it will send the current
# services list. If the list changes the visa service will resend it with a higher
# version number.
#
# The visa service pushes visas and visa revocations to the node as the need
# arises. These must be acknowledged by the node before the visa service updates
# its state. In the acknowledgement step, the node can indicate how many of the
# passed visa operations (grants and revocations) were processed. The visa service
# will retry pushes until all are acknowledged.
#
# The visa service never purposely sends a visa revocation before sending the visa
# it refers to. However, if a node ever receives a visa revocation for an unknown
# visa, it should acknowledge it, log the irregular event and continue on.
#
# Various network errors could cause visas to be sent multiple times to a node.
# The node should acknowledge and log, but not re-install any duplicate visas
# (detected by their unique visa ID) that arrive.



# ###################################################
#                 VS-API RPC SCHEMA
# ###################################################

interface VisaService {
  connect   @0 (req :VSConnectRequest) -> (resp :Result(VSGate));
}

interface VSGate {
  challenge    @0 () -> (challenge: Challenge);
  authenticate @1 (cresp: ChallengeResponse) -> (res :Result(VSHandle));
}

interface VSHandle {
  registerVss       @0 (addr: SockAddr) -> (res :Result(List(VisaOp))); 

  authorizeConnect  @1 (req :ConnectRequest) -> (resp :Result(Connection));
  reauthorize       @2 (req :ReauthRequest) -> (resp :Result(Connection));
  notifyDisconnect  @3 (req :DisconnectNotice) -> (res :OkOrError);

  visaRequest       @4 (req :VisaRequest) -> (resp :VisaResponse);

  ping              @5 () -> (res :OkOrError);
}

struct OkOrError {
  union {
    ok @0 :Void;
    error @1 :Error;
  }
}

struct Result(T) {
  union {
    ok @0 :T;
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
  blobs    @1 :List(AuthBlob);
}

struct AuthBlob {
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

struct ConnectRequest {
  blobs          @0 :List(AuthBlob);
  claims         @1 :List(Claim);
  substrateAddr  @2 :IpAddr;
  dockInterface  @3 :UInt8;  # zero means 'unspecified/default'
}


struct Claim {
  key   @0 :Text;
  value @1 :Text;
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
  authError              @8;
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


# ###################################################
#                VSS-API RPC SCHEMA
# ###################################################

interface VisaSupportService {
  connect @0 (req: VSSConnectRequest) -> (resp: Result(VSSHandle));
}

# TODO: Information about policy and topology 
interface VSSHandle {
  pushVisaOp            @0 (ops :List(VisaOp)) -> (ack :Ack);
  revokeAuthentication  @1 (addrs :List(IpAddr)) -> (ack :Ack);
  setServices           @2 (version :UInt64, svcs :List(ServiceDescriptor)) -> (res :OkOrError);
  ping                  @3 () -> (res :OkOrError);
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


