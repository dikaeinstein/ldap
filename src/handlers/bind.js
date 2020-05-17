/**
 * Handle LDAP bind operation
 * @param {import('ldapjs')} ldap
 */
const bindHandler = (ldap) => (req, res, next) => {
  if (req.dn.toString() !== 'cn=root' || req.credentials !== 'secret') {
    return next(new ldap.InvalidCredentialsError());
  }

  res.end();
  return next();
}

module.exports = bindHandler;
