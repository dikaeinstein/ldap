const fs = require('fs');
const util = require('util');

const readFileAsync = util.promisify(fs.readFile);

/**
 * Parse each `/etc/passwd` line
 *
 * @param {string} line
 * @param {*} req
 */
const parseLine = (line, req) => {
  if (/^#/.test(line)) {
    return;
  }

  const attributes = line.split(':');
  if (!attributes || !attributes.length) {
    return;
  }

  req.users[attributes[0]] = {
    dn: `cn=${attributes[0]}, ou=users, o=myhost`,
    attributes: {
      cn: attributes[0],
      uid: attributes[2],
      gid: attributes[3],
      description: attributes[4],
      homedirectory: attributes[5],
      shell: attributes[6] || '',
      objectclass: 'unixUser'
    }
  }
}

/**
 *
 * @param {import('ldapjs')} ldap
 */
const loadPasswdFile = (ldap) => async (req, res, next) => {
  try {
    const data = await readFileAsync('/etc/passwd', { encoding: 'utf8' })

    req.users = {};

    const lines = data.split('\n');
    for (const line of lines) {
      parseLine(line, req);
    }

    next();
  } catch (error) {
    next(new ldap.OperationsError(error));
  }
}

module.exports = loadPasswdFile;
