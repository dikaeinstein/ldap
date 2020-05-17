/**
 * @callback SearchHandler
 * @param {import('ldapjs').SearchRequest} req
 * @param {*} res
 * @param {*} next
 */

/**
 * Handles LDAP search operation
 * @returns {SearchHandler}
 */
const searchHandler = (req, res, next) => {
  Object.keys(req.users).forEach((k) => {
    if (req.filter.matches(req.users[k].attributes)) {
      res.send(req.users[k]);
    }
  });

  res.end();
  return next();
};

module.exports = searchHandler;
