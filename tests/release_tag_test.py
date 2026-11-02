import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


WORKFLOWS = Path(__file__).resolve().parents[1] / '.github/workflows'


def step_script(filename, name):
    text = (WORKFLOWS / filename).read_text()
    step = text.split('      - name: ' + name + '\n', 1)[1].split('      - ', 1)[0]
    script = step.split('        run: |\n', 1)[1]
    return '\n'.join(line[10:] for line in script.splitlines())


class ReleaseTagTests(unittest.TestCase):
    def test_linux_matrix_and_musl_linkers(self):
        workflow = (WORKFLOWS / 'binary-build.yml').read_text()
        matrix = workflow.split('        include:\n', 1)[1].split('    steps:', 1)[0]
        entries = re.findall(r'- os: (\S+)\s+target: (\S+)', matrix)
        self.assertEqual(entries, [
            ('ubuntu-latest', 'x86_64-unknown-linux-gnu'),
            ('ubuntu-latest', 'aarch64-unknown-linux-gnu'),
            ('ubuntu-24.04', 'x86_64-unknown-linux-musl'),
            ('ubuntu-24.04-arm', 'aarch64-unknown-linux-musl'),
        ])
        self.assertIn("if: endsWith(matrix.target, '-musl')", workflow)
        self.assertIn('sudo apt-get install -y musl-tools',
                      step_script('binary-build.yml', 'Install musl toolchain'))
        for arch in ['X86_64', 'AARCH64']:
            self.assertIn(f'CARGO_TARGET_{arch}_UNKNOWN_LINUX_MUSL_LINKER: musl-gcc', workflow)
        self.assertIn('targets: ${{ matrix.target }}', workflow)
        self.assertIn('cargo build --release --target ${{ matrix.target }}', workflow)
        self.assertIn("if: matrix.target == 'x86_64-unknown-linux-gnu'", workflow)

    def test_all_linux_asset_names_preserve_binary_contents(self):
        for arch in ['x86_64', 'aarch64']:
            for libc in ['gnu', 'musl']:
                target = f'{arch}-unknown-linux-{libc}'
                with self.subTest(target=target), tempfile.TemporaryDirectory() as temp:
                    root = Path(temp)
                    binary = root / 'target' / target / 'release/u2secure'
                    binary.parent.mkdir(parents=True)
                    binary.write_bytes(b'binary-fixture')
                    script = step_script('binary-build.yml', 'Rename binary with platform suffix')
                    result = subprocess.run(
                        ['bash', '-e', '-o', 'pipefail', '-c',
                         script.replace('${{ matrix.target }}', target)],
                        cwd=root, capture_output=True, text=True, timeout=10,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual((root / f'u2secure-{target}').read_bytes(), binary.read_bytes())

    def run_step(self, filename, name, env, root):
        output = root / 'output'
        output.write_text('')
        result = subprocess.run(
            ['bash', '-e', '-o', 'pipefail', '-c', step_script(filename, name)],
            env={**os.environ, **env, 'RUNNER_TEMP': str(root), 'GITHUB_OUTPUT': str(output)},
            capture_output=True, text=True, timeout=10,
        )
        return result, dict(line.split('=', 1) for line in output.read_text().splitlines())

    def test_actual_built_tag_is_used_by_both_publishers(self):
        for event, ref, tag in [
            ('push', 'refs/tags/v0.4.1', ''),
            ('workflow_dispatch', 'refs/heads/main', 'v0.4.1'),
            ('workflow_dispatch', 'refs/tags/v0.4.1', 'v0.4.1'),
        ]:
            with self.subTest(event=event, ref=ref), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                result, built = self.run_step('binary-build.yml', 'Determine release tag', {
                    'EVENT_NAME': event, 'GITHUB_REF': ref, 'INPUT_TAG': tag,
                }, root)
                self.assertEqual(result.returncode, 0, result.stderr)
                for filename, name in [
                    ('npm-publish-manual.yml', 'Normalize version'),
                    ('cargo-publish.yml', 'Resolve release tag'),
                ]:
                    result, published = self.run_step(filename, name, {'EVENT_NAME': 'workflow_run'}, root)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(published['tag'], built['tag'])
                    workflow = (WORKFLOWS / filename).read_text()
                    self.assertIn("github.event.workflow_run.conclusion == 'success'", workflow)
                    self.assertIn('run-id: ${{ github.event.workflow_run.id }}', workflow)
                    self.assertNotIn('head_branch', workflow)
                    output_id = 'version' if filename.startswith('npm') else 'tag'
                    self.assertIn('ref: ${{ steps.' + output_id + '.outputs.tag }}', workflow)

    def test_manual_publish_and_invalid_metadata(self):
        for filename, name in [
            ('npm-publish-manual.yml', 'Normalize version'),
            ('cargo-publish.yml', 'Resolve release tag'),
        ]:
            for value in ['0.4.1', 'v0.4.1', 'v0.5.0-rc.1', 'main', 'v1.2.3/evil', 'v1.2.3\nv9.9.9', '']:
                with self.subTest(file=filename, value=value), tempfile.TemporaryDirectory() as temp:
                    root = Path(temp)
                    result, output = self.run_step(filename, name, {
                        'EVENT_NAME': 'workflow_dispatch', 'INPUT_REF': value,
                    }, root)
                    self.assertEqual(result.returncode == 0, value in ['0.4.1', 'v0.4.1', 'v0.5.0-rc.1'])
                    if result.returncode == 0:
                        self.assertEqual(output['tag'], 'v' + value.removeprefix('v'))
            with tempfile.TemporaryDirectory() as temp:
                result, _ = self.run_step(filename, name, {'EVENT_NAME': 'workflow_run'}, Path(temp))
                self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()
