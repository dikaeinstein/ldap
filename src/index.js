const ldap = require('ldapjs');

// handlers
const addHandler = require('./handlers/add');
const authorize = require('./handlers/authorize');
const bindHandler = require('./handlers/bind');
const deleteHandler = require('./handlers/delete');
const loadPasswdFile = require('./handlers/loadPasswdFile');
const modifyHandler = require('./handlers/modify');
const searchHandler = require('./handlers/search');

const server = ldap.createServer();

const pre = [authorize(ldap), loadPasswdFile(ldap)];

server.add('ou=users, o=myhost', pre, addHandler(ldap));
server.bind('cn=root', bindHandler(ldap));
server.del('ou=users, o=myhost', pre, deleteHandler(ldap));
server.modify('ou=users, o=myhost', pre, modifyHandler(ldap));
server.search('o=myhost', pre, searchHandler);

server.listen(1389, () => {
  console.log('/etc/passwd LDAP server up at:', server.url);
});
