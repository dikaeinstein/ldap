const { spawn } = require('child_process');

const validateDelLDIF = (ldap, req) => {
  const { cn } = req.dn.rdns[0].attrs;
  if (!cn || !req.users[cn]) {
    throw new ldap.NoSuchObjectError(req.dn.toString());
  }
}

const execUserDelCmd = (req, res, next) => {
  const { cn } = req.dn.rdns[0].attrs;

  const userdel = spawn('userdel', ['-f', cn]);

  const messages = [];
  userdel.stdout.on('data', (data) => {
    messages.push(data.toString());
  });
  userdel.stderr.on('data', (data) => {
    messages.push(data.toString());
  });
  userdel.on('error', err => console.error(err));
  userdel.on('exit', (code) => {
    if (code !== 0) {
      var msg = `${code}`;
      if (messages.length) {
        msg += `: ${messages.join()}`;
      }
      throw new ldap.OperationsError(msg);
    }

    res.end();
    return next();
  });
}

/**
 * Handle LDAP delete operation
 * @param {import('ldapjs')} ldap
 */
const deleteHandler = (ldap) => (req, res, next) => {
  try {
    validateDelLDIF(ldap, req);

    execUserDelCmd(req, res, next);
  } catch (error) {
    next(error);
  }
}

module.exports = deleteHandler;
