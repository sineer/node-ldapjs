// Copyright 2011 Mark Cavage, Inc.  All rights reserved.

var assert = require('assert');
var util = require('util');

var asn1 = require('asn1');

var LDAPMessage = require('./message');
var LDAPResult = require('./result');

var SASLFactory = require('saslmechanisms');

var dn = require('../dn');
var Protocol = require('../protocol');

///--- Globals

var Ber = asn1.Ber;

var LDAP_BIND_SIMPLE = 'Simple';
var LDAP_BIND_GSSAPI = 'GSSAPI';


///--- API

function BindRequest(options) {
  if (options && typeof (options) !== 'object')
    throw new TypeError('options must be an object');

  options = options || {};

  options.protocolOp = Protocol.LDAP_REQ_BIND;
  LDAPMessage.call(this, options);

  this.version = options.version || 0x03;
  this.name = options.name || null;

  this.authentication = options.authentication || options.saslMechanism; // SASL AUTH MECHANISM
  this.credentials    = options.credentials || '';

  if (this.authentication != LDAP_BIND_SIMPLE) {

    // Try using JS-SASL FACTORY to instanciate mechanism...
    if (options.saslFactory ) {
      this.mechanism = options.saslFactory.create(this.authentication);

      this.authentication = this.mechanism.name;
    }
    if ( !this.mechanism ) {
      throw new Error('Failed to instanciate SASL authentication mechanism: ' 
                      + this.authentication);
    }
  }
    
  var self = this;
  this.__defineGetter__('type', function () { return 'BindRequest'; });
  this.__defineGetter__('_dn', function () { return self.name; });
}
util.inherits(BindRequest, LDAPMessage);
module.exports = BindRequest;


BindRequest.prototype._parse = function (ber) {
  assert.ok(ber);

  this.version = ber.readInt();
  this.name = dn.parse(ber.readString());

  var mech = ber.peek();

  if (mech === Ber.Context) {
    // SIMPLE AUTH MECHANISM
    this.authentication = LDAP_BIND_SIMPLE;
    this.credentials = ber.readString(Ber.Context);
  } else if (mech === (Ber.Constructor | Ber.Sequence)) {
    // SASL AUTH MECHANISM
    ber.readSequence();
    mech = ber.readString(Ber.Context);

      console.log("SASL AUTH MECH:" + mech);
      this.authentication = mech;

      // TODO:

      var cred = ber.peek();

      if (cred === Ber.Context) {
        // OPTIONAL SASL CREDs
        this.credentials = ber.readString(Ber.Context);
      }
  } else {    
    throw new Error('authentication mechanish 0x' + mech.toString(16) + ' not supported');
  }

  return true;
};


BindRequest.prototype._toBer = function (ber) {
  assert.ok(ber);

  ber.writeInt(this.version);
  ber.writeString((this.name || '').toString());

  switch( this.authentication ) {
  case LDAP_BIND_SIMPLE:
    // SIMPLE AUTH MECHANISM
    ber.writeString((this.credentials || ''), Ber.Context);
    break;

  case LDAP_BIND_GSSAPI:
    // SASL GSSAPI AUTH MECHANISM

    var saslCreds = this.mechanism.challenge(this.credentials);

    ber.startSequence();
    ber.writeString(LDAP_BIND_GSSAPI, Ber.Context); // SASL MECHANISM        
    ber.writeString(saslCreds, Ber.Context); // SASL CREDENTIALS
    ber.endSequence();
    break;

  default:
    // ERR, UNSUPPORTED AUTH MECHANISM
    throw new TypeError('UNSUPPORTED Authentication Mechanish: ' + this.authentication);
  }

  return ber;
};


BindRequest.prototype._json = function (j) {
  assert.ok(j);

  j.version = this.version;
  j.name = this.name;
  j.authenticationType = this.authentication;
  j.credentials = this.credentials;

  return j;
};

