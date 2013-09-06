// Copyright 2013 SINEER Inc. All rights reserved.

var Logger = require('bunyan');

var test = require('tap').test;
var uuid = require('node-uuid');

var ldap = require('../lib/index');


///--- Globals

var BIND_DN = 'cn=root';
var BIND_PW = 'secret';
var SOCKET = '/tmp/.' + uuid();

///--- SASL Tests

test('setup', function (t) {
    Attribute = ldap.Attribute;
    Change = ldap.Change;

    server = ldap.createServer();
    t.ok(server);

    server.bind(BIND_DN, function (req, res, next) {

        if (req.authentication !== 'GSSAPI')
            return next(new ldap.InvalidCredentialsError('Invalid Authentication Mechanism:' 
                                                         + req.authentication));

        if (req.credentials !== BIND_PW)
            return next(new ldap.InvalidCredentialsError('Invalid password'));

        res.end();
        return next();
    });

    server.unbind(function (req, res, next) {
        res.end();
        return next();
    });

    server.listen(SOCKET, function () {
        client = ldap.createClient({
            connectTimeout: parseInt(process.env.LDAP_CONNECT_TIMEOUT || 0, 10),
            socketPath: SOCKET,
            maxConnections: parseInt(process.env.LDAP_MAX_CONNS || 5, 10),
            idleTimeoutMillis: 10,
            log: new Logger({
                name: 'ldapjs_unit_test',
                stream: process.stderr,
                level: (process.env.LOG_LEVEL || 'info'),
                serializers: Logger.stdSerializers,
                src: true
            })
        });
        t.ok(client);
        t.end();
    });

});


test('SASL bind failure', function (t) {
    client.bind(BIND_DN, 'foo', 'GSSAPI', function (err, res) {
        t.ok(err);
        t.notOk(res);

        t.ok(err instanceof ldap.InvalidCredentialsError);
        t.ok(err instanceof Error);
        t.ok(err.dn);
        t.ok(err.message);
        t.ok(err.stack);

        t.end();
    });
});


test('SASL bind success', function (t) {
    client.bind(BIND_DN, 'secret', 'GSSAPI', function (err, res) {
        t.ifError(err);
        t.ok(res);
        console.log("RES:");
        console.dir(res);

        if(res) t.equal(res.status, 0);
        t.end();
    });
});

test('shutdown', function (t) {
  server.on('close', function () {
    t.end();
  });
  server.close();
});
