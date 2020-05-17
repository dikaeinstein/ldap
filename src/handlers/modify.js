const { spawn } = require('child_process');

const validateModifyLDIF = (ldap, req) => {
  const { cn } = req.dn.rdns[0].attrs;
  if (!cn || !req.users[cn]) {
    throw new ldap.NoSuchObjectError(req.dn.toString());
  }

  if (!req.changes.length) {
    throw new ldap.ProtocolError('changes required');
  }

  let mod;

  for (const change of req.changes) {
    mod = change.modification;
    switch (change.operation) {
      case 'replace':
        if (mod.type !== 'userpassword' || !mod.vals || !mod.vals.length) {
          throw new ldap.UnwillingToPerformError('only password updates allowed');
        }
        break;
      case 'add':
      case 'delete':
        throw new ldap.UnwillingToPerformError('only replace allowed');
    }
  }

  return mod;
}

const execChPasswdCmd = (user, mod, res, next) => {
  const passwd = spawn('chpasswd', ['-c', 'MD5']);
  passwd.stdin.end(`${user.cn}:${mod.vals[0]}`, 'utf8');

  passwd.on("error", (err) => console.error(err));
  passwd.on('exit', (code) => {
    if (code !== 0) {
      throw new ldap.OperationsError(code);
    }

    res.end();
    return next();
  });
}

/**
 * Handles modify LDAP operation
 * @param {import('ldapjs')} ldap
 */
const modifyHandler = (ldap) => (req, res, next) => {
  try {
    const mod = validateModifyLDIF(ldap, req);

    const user = req.users[req.dn.rdns[0].cn].attributes;

    execChPasswdCmd(user, mod, res, next);
  } catch (error) {
    next(error);
  }
}

module.exports = modifyHandler;
