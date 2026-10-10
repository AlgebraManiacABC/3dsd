"""Command-line entry point: python -m 3dsd <command> ...

Each command imports only what it uses. Ninja starts a fresh process for every
compile step -- thousands of them on a large project -- so keeping yaml and the
project loader out of that path is worth the function-level imports.
"""
# pylint: disable=import-outside-toplevel

import argparse
import sys
from pathlib import Path

from .util import PipelineError


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='3dsd',
        description='CTR (3DS) decompilation pipeline with Ninja integration',
    )
    sub = parser.add_subparsers(dest='command', required=True)

    def project_command(name: str, help_text: str, single_binary: bool = True):
        p = sub.add_parser(name, help=help_text)
        p.add_argument('dir', help='Project working directory')
        if single_binary:
            p.add_argument('--single-binary', metavar='NAME',
                           help='Operate on only this binary')
        return p

    p_split = project_command('split', 'Split original binaries into per-symbol ELF objects')
    p_split.add_argument('--no-progress', action='store_true')

    p_ninja = project_command('ninja', 'Generate build.ninja')
    p_ninja.add_argument('--roundtrip', action='store_true',
                         help='Also emit the byte-perfect rebuild (relink the '
                              'split and verify it)')

    project_command('objdiff', 'Generate objdiff.json')

    p_build = project_command('build', 'Run ninja build', single_binary=False)
    p_build.add_argument('-j', '--jobs', type=int, default=None,
                         help='Number of parallel jobs')
    p_build.add_argument('-k', '--keep-going', action='store_true',
                         help='Keep going on errors')
    p_build.add_argument('--roundtrip', action='store_true',
                         help='Also split and relink the originals, verifying '
                              'the rebuild is byte-perfect. Off by default: it '
                              'tests the pipeline, not the decomp, and costs a '
                              'split and link of every symbol in every binary')
    p_build.add_argument('targets', nargs='*', default=None,
                         help='Ninja targets (e.g. "compile")')

    project_command('check', 'Verify recreated binaries against originals')

    p_clean = project_command('clean', 'Remove generated build output', single_binary=False)
    p_clean.add_argument('targets', nargs='*',
                         help='build, split, link, out, ninja, objdiff, all '
                              '(default: everything except split)')
    p_clean.add_argument('-n', '--dry-run', action='store_true',
                         help='List what would be removed without deleting')

    project_command('progress', 'Report matching/in-progress function stats')

    # --- internal commands, run by the rules in build.ninja ---
    p_compile = sub.add_parser('compile', help='Compile source file (internal)')
    p_compile.add_argument('--source', required=True)
    p_compile.add_argument('--output', required=True)
    p_compile.add_argument('--cc', required=True, dest='cc_path')
    p_compile.add_argument('--flags', default='')

    p_lb = sub.add_parser('link-base', help='Link the objdiff base ELF (internal)')
    p_lb.add_argument('--ld', required=True)
    p_lb.add_argument('--output', required=True)
    p_lb.add_argument('--rsp', required=True)

    p_cro = sub.add_parser('cro-from-elf',
                           help='Flatten a linked ELF into a CRO module (internal)')
    p_cro.add_argument('--linked', required=True)
    p_cro.add_argument('--original', required=True)
    p_cro.add_argument('--output', required=True)
    p_cro.add_argument('--objcopy', required=True)

    p_chkfile = sub.add_parser('check-file', help='Verify a single binary (internal)')
    p_chkfile.add_argument('--original', required=True)
    p_chkfile.add_argument('--built', required=True)
    p_chkfile.add_argument('--stamp', required=True,
                           help='Written on a match, removed on a mismatch')

    return parser


def _load(args: argparse.Namespace):
    from .config import ProjectConfig
    return ProjectConfig.load(Path(args.dir), args.single_binary)


def _run(args: argparse.Namespace) -> int:  # pylint: disable=too-many-return-statements
    """Dispatch one parsed command; returns the process exit code."""
    match args.command:
        case 'split':
            from .split import run_split
            run_split(_load(args), not args.no_progress)
        case 'ninja':
            from .ninja import generate_ninja
            generate_ninja(_load(args), args.roundtrip)
        case 'objdiff':
            from .objdiff import generate_objdiff
            generate_objdiff(_load(args))
        case 'build':
            from .build import run_build
            ok = run_build(Path(args.dir), args.jobs, args.keep_going,
                           args.targets, args.roundtrip)
            return 0 if ok else 1
        case 'check':
            from .check import run_check
            return 0 if run_check(_load(args)) else 1
        case 'clean':
            from .clean import run_clean
            return 0 if run_clean(Path(args.dir), args.targets, args.dry_run) else 1
        case 'progress':
            from .objdiff import report_progress
            report_progress(_load(args))
        case 'compile':
            from .compiler import compile_source
            compile_source(
                source=Path(args.source),
                output=Path(args.output),
                cc=Path(args.cc_path),
                flags=args.flags.split(',') if args.flags else [],
            )
        case 'link-base':
            from .objdiff import link_base
            return link_base(Path(args.ld), Path(args.output), Path(args.rsp))
        case 'cro-from-elf':
            from .recreate import cro_from_elf
            cro_from_elf(Path(args.linked), Path(args.original),
                         Path(args.output), Path(args.objcopy))
        case 'check-file':
            from .check import verify_file
            ok = verify_file(Path(args.original), Path(args.built), Path(args.stamp))
            return 0 if ok else 1
    return 0


def main():
    """Parse the command line and run it, exiting with its status."""
    args = _build_parser().parse_args()
    try:
        status = _run(args)
    except PipelineError as e:
        print(f"Error: {e}", file=sys.stderr)
        status = 1
    sys.exit(status)


if __name__ == '__main__':
    main()
