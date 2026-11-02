const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');
const { spawnSync } = require('node:child_process');
const { IncomingMessage } = require('node:http');
const { Socket } = require('node:net');
const { EventEmitter } = require('node:events');

if (process.argv[2] === 'child') {
  const [dir, mode] = process.argv.slice(3);
  const yaml = fs.readFileSync(path.join(__dirname, '../.github/workflows/npm-publish-manual.yml'), 'utf8');
  const source = yaml.match(/cat > bin\/install.js <<'INSTALL_JS'\n([\s\S]*?)\n          INSTALL_JS/)[1]
    .split('\n').map(line => line.slice(10)).join('\n');
  function mockRequire(name) {
    if (name === 'os') return { platform: () => 'linux', arch: () => 'x64' };
    if (name === '../package.json') return {
      version: '0.4.1', repository: { url: 'git+https://github.com/cherish-ltt/U2Secure.git' },
    };
    if (name === 'follow-redirects') return { https: { get(url, callback) {
      const request = new EventEmitter();
      process.nextTick(() => {
        if (mode === 'request-error') return request.emit('error', new Error('request failed'));
        const response = new IncomingMessage(new Socket());
        response.statusCode = mode === 'http-error' ? 404 : 200;
        response.headers = { 'content-length': mode === 'length-mismatch' ? '99' : '14' };
        callback(response);
        response.push(Buffer.from('harmless-bytes'));
        setImmediate(() => {
          if (mode === 'abort') response.destroy(new Error('aborted'));
          else { response.complete = true; response.push(null); }
        });
      });
      return request;
    } } };
    if (name === 'fs' && mode === 'write-error') return {
      ...fs, createWriteStream() {
        return new (require('node:stream').Writable)({
          write(chunk, encoding, callback) { callback(new Error('disk write failed')); },
        });
      },
    };
    return require(name);
  }
  vm.runInNewContext(source, { require: mockRequire, __dirname: dir, console, process });
} else {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'npm-install-'));
  try {
    for (const mode of ['complete', 'abort', 'http-error', 'request-error', 'write-error', 'length-mismatch']) {
      for (const existing of [false, true]) {
        const dir = path.join(root, `${mode}-${existing}`);
        fs.mkdirSync(path.join(dir, 'native'), { recursive: true });
        const target = path.join(dir, 'native/u2secure');
        if (existing) fs.writeFileSync(target, 'previous-complete-binary');
        const result = spawnSync(process.execPath, [__filename, 'child', dir, mode], { encoding: 'utf8', timeout: 10000 });
        assert.ifError(result.error);
        if (mode === 'complete') {
          assert.equal(result.status, 0, result.stderr);
          assert.equal(fs.readFileSync(target, 'utf8'), 'harmless-bytes');
          assert.equal(fs.statSync(target).mode & 0o777, 0o755);
        } else {
          assert.notEqual(result.status, 0, `${mode} must fail`);
          assert.ok(result.stderr.length > 0, `${mode} must report the error`);
          assert.equal(fs.existsSync(target), existing);
          if (existing) assert.equal(fs.readFileSync(target, 'utf8'), 'previous-complete-binary');
        }
        assert.deepEqual(fs.readdirSync(path.join(dir, 'native')), fs.existsSync(target) ? ['u2secure'] : []);
        console.log(`PASS ${mode}, existing=${existing}`);
      }
    }
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}
