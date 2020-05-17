/**
 * Authorize users
 * @param {import('ldapjs')} ldap
 */
const authorize = (ldap) => (req, res, next) => {
  if (!req.connection.ldap.bindDN.equals('cn=root'))
    return next(new ldap.InsufficientAccessRightsError());

  return next();
}

module.exports = authorize;
