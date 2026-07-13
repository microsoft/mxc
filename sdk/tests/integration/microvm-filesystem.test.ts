// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// MicroVM SDK end-to-end tests — these tests spawn NanVix VMs via wxc-exec.exe.
//
// Requirements:
//   - Windows with WHP enabled (bcdedit /set hypervisorlaunchtype auto)
//   - wxc-exec.exe built (in src/target/debug/ or src/target/x86_64-pc-windows-msvc/debug/)
//   - NanVix binaries next to wxc-exec.exe: nanvixd.exe, kernel.elf, python3.12, nanvix_rootfs.img
//
// Run: cd sdk/tests/integration && npx tsc -p tsconfig.json && node --test dist/microvm-filesystem.test.js
//
// All tests use spawnSandboxFromConfig with usePty:false (non-PTY mode).
// PTY mode is not supported for the MicroVM backend.

import { describe, it } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import os from 'os';
import { execSync } from 'child_process';
import { ChildProcess } from 'child_process';
import { sdk } from './test-helpers.js';
import type { ContainerConfig } from '@microsoft/mxc-sdk';

function isWhpAvailable(): boolean {
  if (os.platform() !== 'win32') return false;
  // CI sets this when wxc-exec/nanvix binaries aren't available.
  if (process.env.MXC_SKIP_OS_BUILD_DEPENDENT_TESTS === '1') return false;
  try {
    const result = execSync(
      'powershell -NoProfile -Command "(Get-CimInstance Win32_ComputerSystem).HypervisorPresent"',
      { encoding: 'utf8', timeout: 5000 }
    ).trim();
    return result === 'True';
  } catch {
    return false;
  }
}

const isMicrovmAvailable = isWhpAvailable();

/** Escape backslashes for embedding a Windows path in a Python string literal. */
function pyEscape(p: string): string {
  return p.replace(/\\/g, '\\\\');
}

/**
 * Spawn a microvm sandbox using spawnSandboxFromConfig with usePty:false.
 * Returns stdout, stderr, and exit code.
 */
function runMicrovm(
  config: ContainerConfig,
  options: { timeoutMs?: number } = {},
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  return new Promise((resolve, reject) => {
    const timeout = options.timeoutMs ?? 120_000;

    try {
      const child: ChildProcess = sdk.spawnSandboxFromConfig(config, {
        experimental: true,
        debug: true,
        usePty: false,
      });

      let stdout = '';
      let stderr = '';

      child.stdout?.on('data', (data: Buffer) => { stdout += data.toString(); });
      child.stderr?.on('data', (data: Buffer) => { stderr += data.toString(); });

      const timer = setTimeout(() => {
        child.kill();
        reject(new Error(`MicroVM test timed out after ${timeout}ms.\nstdout: ${stdout}\nstderr: ${stderr}`));
      }, timeout);

      child.on('error', (error: Error) => {
        clearTimeout(timer);
        reject(new Error(`Failed to spawn wxc-exec: ${error.message}`));
      });

      child.on('close', (code: number | null) => {
        clearTimeout(timer);
        resolve({ stdout, stderr, exitCode: code ?? -1 });
      });
    } catch (error) {
      reject(error);
    }
  });
}

describe('MicroVM SDK E2E — spawnSandboxFromConfig with containment: microvm', {
  skip: !isMicrovmAvailable ? 'MicroVM tests require Windows with WHP' : undefined,
}, () => {

  it('should run a simple Python script and capture output', async () => {
    const config = {
      version: '0.6.0-alpha',
      containment: 'microvm' as const,
      process: {
        commandLine: "print('Hello from MicroVM SDK E2E!')",
        timeout: 30000,
      },
    };

    const { stdout, stderr, exitCode } = await runMicrovm(config);
    const combined = stdout + stderr;
    assert.strictEqual(exitCode, 0, `Expected exit code 0, got ${exitCode}.\nstdout: ${stdout}\nstderr: ${stderr}`);
    assert.ok(combined.includes('Hello from MicroVM SDK E2E!'), `Expected greeting in output:\n${combined}`);
  });

  it('should propagate non-zero exit codes', async () => {
    const config = {
      version: '0.6.0-alpha',
      containment: 'microvm' as const,
      process: {
        commandLine: "import sys; sys.exit(42)",
        timeout: 30000,
      },
    };

    const { exitCode } = await runMicrovm(config);
    assert.strictEqual(exitCode, 42, `Expected exit code 42, got ${exitCode}`);
  });

  it('should run multiline scripts with imports', async () => {
    const config = {
      version: '0.6.0-alpha',
      containment: 'microvm' as const,
      process: {
        commandLine: [
          "import sys",
          "import json",
          "result = {'python': f'{sys.version_info.major}.{sys.version_info.minor}', 'platform': sys.platform}",
          "print(json.dumps(result))",
        ].join('\n'),
        timeout: 30000,
      },
    };

    const { stdout, stderr, exitCode } = await runMicrovm(config);
    const combined = stdout + stderr;
    assert.strictEqual(exitCode, 0, `Expected exit code 0.\nstdout: ${stdout}\nstderr: ${stderr}`);
    assert.ok(combined.includes('"platform": "nanvix"'), `Expected nanvix platform in output:\n${combined}`);
  });

  it('should support readwritePaths with transparent path translation', async () => {
    const testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mxc-microvm-e2e-'));
    const rwDir = path.join(testDir, 'work');
    fs.mkdirSync(rwDir);
    fs.writeFileSync(path.join(rwDir, 'input.txt'), 'data from host');

    try {
      // Use the host path directly in the script — the staging layer rewrites
      // it to the guest mount path before the script reaches the VM.
      const config = {
        version: '0.6.0-alpha',
        containment: 'microvm' as const,
        process: {
          commandLine: [
            "import os",
            `path = '${pyEscape(rwDir)}'`,
            "print(f'Guest path: {path}')",
            "with open(os.path.join(path, 'input.txt')) as f:",
            "    print(f'Read: {f.read().strip()}')",
          ].join('\n'),
          timeout: 30000,
        },
        filesystem: {
          readwritePaths: [rwDir],
        },
      };

      const { stdout, stderr, exitCode } = await runMicrovm(config);
      const combined = stdout + stderr;
      assert.strictEqual(exitCode, 0, `Expected exit code 0.\nstdout: ${stdout}\nstderr: ${stderr}`);
      assert.ok(combined.includes('Guest path: /mnt/rw/'), `Expected guest path starting with /mnt/rw/ in output:\n${combined}`);
      assert.ok(combined.includes('Read: data from host'), `Expected host data in output:\n${combined}`);
    } finally {
      fs.rmSync(testDir, { recursive: true, force: true });
    }
  });

  it('should reject denied_paths with an error', async () => {
    const config = {
      version: '0.6.0-alpha',
      containment: 'microvm' as const,
      process: {
        commandLine: "print('should not run')",
        timeout: 30000,
      },
      filesystem: {
        deniedPaths: ['/secret'],
      },
    };

    const { stdout, stderr, exitCode } = await runMicrovm(config);
    const combined = stdout + stderr;
    assert.notStrictEqual(exitCode, 0, `Expected non-zero exit code for denied_paths`);
    assert.ok(combined.includes('denied_paths'), `Expected denied_paths error in output:\n${combined}`);
  });

  it('should copy readwritePaths changes back to the host on clean exit', async () => {
    const testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mxc-microvm-copyback-'));
    const rwDir = path.join(testDir, 'work');
    fs.mkdirSync(rwDir);
    fs.writeFileSync(path.join(rwDir, 'input.txt'), 'before');

    try {
      const config = {
        version: '0.6.0-alpha',
        containment: 'microvm' as const,
        process: {
          commandLine: [
            "import os",
            `path = '${pyEscape(rwDir)}'`,
            "with open(os.path.join(path, 'input.txt'), 'w') as f:",
            "    f.write('after')",
            "with open(os.path.join(path, 'created.txt'), 'w') as f:",
            "    f.write('created by guest')",
          ].join('\n'),
          timeout: 30000,
        },
        filesystem: {
          readwritePaths: [rwDir],
        },
      };

      const { stdout, stderr, exitCode } = await runMicrovm(config);
      assert.strictEqual(exitCode, 0, `Expected exit code 0.\nstdout: ${stdout}\nstderr: ${stderr}`);
      assert.strictEqual(fs.readFileSync(path.join(rwDir, 'input.txt'), 'utf8'), 'after');
      assert.strictEqual(fs.readFileSync(path.join(rwDir, 'created.txt'), 'utf8'), 'created by guest');
    } finally {
      fs.rmSync(testDir, { recursive: true, force: true });
    }
  });

  it('should copy readwritePaths changes back after a normal non-zero guest exit', async () => {
    const testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mxc-microvm-copyback-nonzero-'));
    const rwDir = path.join(testDir, 'work');
    fs.mkdirSync(rwDir);

    try {
      const config = {
        version: '0.6.0-alpha',
        containment: 'microvm' as const,
        process: {
          commandLine: [
            "import os, sys",
            `path = '${pyEscape(rwDir)}'`,
            "with open(os.path.join(path, 'nonzero.txt'), 'w') as f:",
            "    f.write('persisted before non-zero exit')",
            "sys.exit(7)",
          ].join('\n'),
          timeout: 30000,
        },
        filesystem: {
          readwritePaths: [rwDir],
        },
      };

      const { exitCode } = await runMicrovm(config);
      assert.strictEqual(exitCode, 7, `Expected exit code 7, got ${exitCode}`);
      assert.strictEqual(
        fs.readFileSync(path.join(rwDir, 'nonzero.txt'), 'utf8'),
        'persisted before non-zero exit'
      );
    } finally {
      fs.rmSync(testDir, { recursive: true, force: true });
    }
  });

  it('should generate a PPTX file in a readwritePath and copy it back to the host', async () => {
    const testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mxc-microvm-pptx-'));
    const rwDir = path.join(testDir, 'output');
    fs.mkdirSync(rwDir);

    try {
      const rwDirPy = pyEscape(rwDir);
      const config = {
        version: '0.6.0-alpha',
        containment: 'microvm' as const,
        process: {
          // Generate a minimal valid PPTX using only stdlib (zipfile + xml).
          // A PPTX is an Office Open XML package — a zip with specific XML parts.
          commandLine: [
            "import zipfile, os",
            `outdir = '${rwDirPy}'`,
            "pptx_path = os.path.join(outdir, 'test.pptx')",
            "ct = '<?xml version=\"1.0\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Default Extension=\"xml\" ContentType=\"application/xml\"/><Override PartName=\"/ppt/presentation.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml\"/></Types>'",
            "rels = '<?xml version=\"1.0\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"ppt/presentation.xml\"/></Relationships>'",
            "pres = '<?xml version=\"1.0\"?><p:presentation xmlns:p=\"http://schemas.openxmlformats.org/presentationml/2006/main\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\"><p:sldMasterIdLst/><p:sldIdLst/><p:sldSz cx=\"9144000\" cy=\"6858000\"/><p:notesSz cx=\"6858000\" cy=\"9144000\"/></p:presentation>'",
            "with zipfile.ZipFile(pptx_path, 'w', zipfile.ZIP_DEFLATED) as z:",
            "    z.writestr('[Content_Types].xml', ct)",
            "    z.writestr('_rels/.rels', rels)",
            "    z.writestr('ppt/presentation.xml', pres)",
            "print(f'PPTX size: {os.path.getsize(pptx_path)} bytes')",
          ].join('\n'),
          timeout: 30000,
        },
        filesystem: {
          readwritePaths: [rwDir],
        },
      };

      const { stdout, stderr, exitCode } = await runMicrovm(config);
      const combined = stdout + stderr;
      assert.strictEqual(exitCode, 0, `Expected exit code 0.\nstdout: ${stdout}\nstderr: ${stderr}`);
      assert.ok(combined.includes('PPTX size:'), `Expected PPTX size in output:\n${combined}`);

      // Verify the PPTX was copied back to the host.
      const pptxPath = path.join(rwDir, 'test.pptx');
      assert.ok(fs.existsSync(pptxPath), `Expected test.pptx at ${pptxPath}`);
      const size = fs.statSync(pptxPath).size;
      assert.ok(size > 0, `Expected non-empty PPTX, got ${size} bytes`);

      // Verify it's a valid zip (PPTX is zip-based).
      const header = Buffer.alloc(4);
      const fd = fs.openSync(pptxPath, 'r');
      fs.readSync(fd, header, 0, 4, 0);
      fs.closeSync(fd);
      assert.strictEqual(header[0], 0x50, 'Expected PK zip header byte 1');
      assert.strictEqual(header[1], 0x4B, 'Expected PK zip header byte 2');
    } finally {
      fs.rmSync(testDir, { recursive: true, force: true });
    }
  });

  it('should generate a dark-themed 3-slide PPTX about MXC and NanVix using python-pptx', async () => {
    const testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mxc-microvm-pptx-dark-'));
    const rwDir = path.join(testDir, 'output');
    fs.mkdirSync(rwDir);

    try {
      const rwDirPy = pyEscape(rwDir);
      const config = {
        version: '0.6.0-alpha',
        containment: 'microvm' as const,
        process: {
          commandLine: [
            // site-packages isn't on sys.path by default in this NanVix build
            "import sys; sys.path.insert(0, '/sysroot/lib/python3.12/site-packages')",
            "import os",
            "from pptx import Presentation",
            "from pptx.util import Inches, Pt, Emu",
            "from pptx.dml.color import RGBColor",
            "from pptx.enum.text import PP_ALIGN",
            "",
            "prs = Presentation()",
            "prs.slide_width = Emu(12192000)",
            "prs.slide_height = Emu(6858000)",
            "",
            "BG = RGBColor(0x1B, 0x1B, 0x2F)",
            "WHITE = RGBColor(0xFF, 0xFF, 0xFF)",
            "BLUE = RGBColor(0x56, 0x9C, 0xD6)",
            "TEAL = RGBColor(0x4E, 0xC9, 0xB0)",
            "GRAY = RGBColor(0xD4, 0xD4, 0xD4)",
            "",
            "def set_bg(slide):",
            "    bg = slide.background",
            "    fill = bg.fill",
            "    fill.solid()",
            "    fill.fore_color.rgb = BG",
            "",
            "def add_text(slide, left, top, width, height, text, font_size, color, bold=False, alignment=PP_ALIGN.LEFT):",
            "    txBox = slide.shapes.add_textbox(left, top, width, height)",
            "    tf = txBox.text_frame",
            "    tf.word_wrap = True",
            "    p = tf.paragraphs[0]",
            "    p.text = text",
            "    p.font.size = Pt(font_size)",
            "    p.font.color.rgb = color",
            "    p.font.bold = bold",
            "    p.alignment = alignment",
            "    return tf",
            "",
            "def add_para(tf, text, font_size, color, bold=False):",
            "    p = tf.add_paragraph()",
            "    p.text = text",
            "    p.font.size = Pt(font_size)",
            "    p.font.color.rgb = color",
            "    p.font.bold = bold",
            "    return tf",
            "",
            "# --- Slide 1: Title ---",
            "blank = prs.slide_layouts[6]",
            "s1 = prs.slides.add_slide(blank)",
            "set_bg(s1)",
            "add_text(s1, Inches(0.8), Inches(1.8), Inches(10), Inches(1.2),",
            "    '\\U0001f680 MXC \\u00d7 NanVix', 44, WHITE, bold=True, alignment=PP_ALIGN.CENTER)",
            "tf1 = add_text(s1, Inches(0.8), Inches(3.2), Inches(10), Inches(1.5),",
            "    'Sandboxed Code Execution with Micro-VM Isolation', 24, BLUE, alignment=PP_ALIGN.CENTER)",
            "add_para(tf1, '', 12, WHITE)",
            "add_para(tf1, '\\U0001f512 Secure  \\u2022  \\u26a1 Fast  \\u2022  \\U0001f30d Cross-Platform', 20, TEAL)",
            "tf1.paragraphs[-1].alignment = PP_ALIGN.CENTER",
            "",
            "# --- Slide 2: Architecture ---",
            "s2 = prs.slides.add_slide(blank)",
            "set_bg(s2)",
            "add_text(s2, Inches(0.8), Inches(0.4), Inches(10), Inches(0.8),",
            "    '\\U0001f527 How It Works', 32, WHITE, bold=True)",
            "tf2 = add_text(s2, Inches(0.8), Inches(1.4), Inches(10), Inches(5),",
            "    '\\U0001f4e6 MXC (Microsoft eXecution Container)', 20, BLUE, bold=True)",
            "add_para(tf2, 'Orchestrates sandboxed execution across backends', 16, GRAY)",
            "add_para(tf2, '', 12, GRAY)",
            "add_para(tf2, '\\U0001f5a5 NanVix Micro-VM Backend', 20, BLUE, bold=True)",
            "add_para(tf2, 'Lightweight hypervisor isolation via WHP', 16, GRAY)",
            "add_para(tf2, 'CPython 3.12 inside a minimal microkernel', 16, GRAY)",
            "add_para(tf2, '', 12, GRAY)",
            "add_para(tf2, '\\U0001f504 The Flow', 20, BLUE, bold=True)",
            "add_para(tf2, 'SDK \\u2192 wxc-exec \\u2192 nanvixd \\u2192 kernel.elf \\u2192 Python \\U0001f40d', 16, TEAL)",
            "",
            "# --- Slide 3: What's Next ---",
            "s3 = prs.slides.add_slide(blank)",
            "set_bg(s3)",
            "add_text(s3, Inches(0.8), Inches(0.4), Inches(10), Inches(0.8),",
            "    '\\u2728 What\\'s Next', 32, WHITE, bold=True)",
            "tf3 = add_text(s3, Inches(0.8), Inches(1.4), Inches(10), Inches(5),",
            "    '\\u2705 Filesystem sharing via readwritePaths', 18, GRAY)",
            "add_para(tf3, '\\u2705 Stdout/stderr streaming back to host', 18, GRAY)",
            "add_para(tf3, '\\u2705 Exit code propagation', 18, GRAY)",
            "add_para(tf3, '\\U0001f6a7 Network isolation & proxy support', 18, GRAY)",
            "add_para(tf3, '\\U0001f6a7 Multi-language guest support', 18, GRAY)",
            "add_para(tf3, '\\U0001f6a7 GPU passthrough for AI workloads', 18, GRAY)",
            "add_para(tf3, '', 12, GRAY)",
            "add_para(tf3, '\\U0001f4ac \"Run untrusted code safely, at VM speed\"', 20, TEAL, bold=True)",
            "",
            `pptx_path = os.path.join('${rwDirPy}', 'mxc-nanvix.pptx')`,
            "prs.save(pptx_path)",
            "size = os.path.getsize(pptx_path)",
            "print(f'PPTX created: {size} bytes, 3 slides')",
            "print(f'Output: {pptx_path}')",
          ].join('\n'),
          timeout: 60000,
        },
        filesystem: {
          readwritePaths: [rwDir],
        },
      };

      const { stdout, stderr, exitCode } = await runMicrovm(config);
      const combined = stdout + stderr;

      assert.strictEqual(exitCode, 0, `Expected exit code 0.\nstdout: ${stdout}\nstderr: ${stderr}`);
      assert.ok(combined.includes('PPTX created:'), `Expected creation message in output:\n${combined}`);
      assert.ok(combined.includes('3 slides'), `Expected 3 slides in output:\n${combined}`);

      // Verify the PPTX was copied back to the host.
      const pptxPath = path.join(rwDir, 'mxc-nanvix.pptx');
      assert.ok(fs.existsSync(pptxPath), `Expected mxc-nanvix.pptx at ${pptxPath}`);
      const size = fs.statSync(pptxPath).size;
      assert.ok(size > 10000, `Expected substantial PPTX from python-pptx, got ${size} bytes`);

      // Verify valid zip with PK header.
      const header = Buffer.alloc(4);
      const fd = fs.openSync(pptxPath, 'r');
      fs.readSync(fd, header, 0, 4, 0);
      fs.closeSync(fd);
      assert.strictEqual(header[0], 0x50, 'Expected PK zip header byte 1');
      assert.strictEqual(header[1], 0x4B, 'Expected PK zip header byte 2');

      console.log(`Dark PPTX output: ${pptxPath} (${size} bytes)`);
    } finally {
      // Keep output for manual inspection — open in PowerPoint to verify.
      console.log(`Dark PPTX test dir persisted at: ${testDir}`);
    }
  });
});
