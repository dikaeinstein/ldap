const { spawn } = require('child_process');

const validateAddLDIF = (ldap, req) => {
  const { cn } = req.dn.rdns[0].attrs;
  if (!cn) {
    throw new ldap.ConstraintViolationError('cn required');
  }

  if (req.users[cn]) {
    throw new ldap.EntryAlreadyExistsError(req.dn.toString());
  }

  const entry = req.toObject().attributes;
  if (entry.objectclass[0] !== 'unixUser') {
    throw new ldap.ConstraintViolationError('entry must be a unixUser');
  }

  return entry;
}

const buildUserAddOptions = (entry) => {
  const opts = ['-m'];

  if (entry.description) {
    opts.push('-c');
    opts.push(entry.description[0]);
  }
  if (entry.homedirectory) {
    opts.push('-d');
    opts.push(entry.homedirectory[0]);
  }
  if (entry.gid) {
    opts.push('-g');
    opts.push(entry.gid[0]);
  }
  if (entry.shell) {
    opts.push('-s');
    opts.push(entry.shell[0]);
  }
  if (entry.uid) {
    opts.push('-u');
    opts.push(entry.uid[0]);
  }
  opts.push(entry.cn[0]);

  return opts;
}

const execUserAddCmd = (opts, res, next) => {
  const useradd = spawn('useradd', opts);

  var messages = [];

  useradd.stdout.on('data', (data) => {
    messages.push(data.toString());
  });
  useradd.stderr.on('data', (data) => {
    messages.push(data.toString());
  });
  useradd.on('error', err => console.error(err));
  useradd.on('exit', (code) => {
    if (code !== 0) {
      let msg = `${code}`;
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
 * Handle LDAP add operation
 * @param {import('ldapjs')} ldap
 */
const addHandler = (ldap) => (req, res, next) => {
  try {
    const entry = validateAddLDIF(ldap, req);

    const opts = buildUserAddOptions(entry);

    execUserAddCmd(opts, res, next);
  } catch (error) {
    next(error);
  }
}

module.exports = addHandler;
