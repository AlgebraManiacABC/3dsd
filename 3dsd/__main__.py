import argparse
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(
        prog='3dsd',
        description='CTR (3DS) decompilation pipeline with Ninja integration',
    )
    sub = parser.add_subparsers(dest='command', required=True)

    # --- split ---
    p_split = sub.add_parser('split', help='Split original binaries into per-symbol ELF objects')
    p_split.add_argument('dir', help='Project working directory')
    p_split.add_argument('--single-binary', metavar='NAME',
                         help='Operate on only this binary')
    p_split.add_argument('--no-progress', action='store_true')

    # --- ninja ---
    p_ninja = sub.add_parser('ninja', help='Generate build.ninja')
    p_ninja.add_argument('dir', help='Project working directory')
    p_ninja.add_argument('--single-binary', metavar='NAME',
                         help='Operate on only this binary')

    # --- objdiff ---
    p_objdiff = sub.add_parser('objdiff', help='Generate objdiff.json')
    p_objdiff.add_argument('dir', help='Project working directory')
    p_objdiff.add_argument('--single-binary', metavar='NAME',
                           help='Operate on only this binary')

    # --- build ---
    p_build = sub.add_parser('build', help='Run ninja build')
    p_build.add_argument('dir', help='Project working directory')
    p_build.add_argument('-j', '--jobs', type=int, default=None,
                         help='Number of parallel jobs')
    p_build.add_argument('-k', '--keep-going', action='store_true',
                         help='Keep going on errors')
    p_build.add_argument('targets', nargs='*', default=None,
                         help='Ninja targets (e.g. "compile")')

    # --- check ---
    p_check = sub.add_parser('check', help='Verify recreated binaries against originals')
    p_check.add_argument('dir', help='Project working directory')
    p_check.add_argument('--single-binary', metavar='NAME',
                         help='Operate on only this binary')

    # --- clean ---
    p_clean = sub.add_parser('clean', help='Remove generated build output')
    p_clean.add_argument('dir', help='Project working directory')
    p_clean.add_argument('targets', nargs='*',
                         help='build, split, link, out, ninja, objdiff, all '
                              '(default: everything except split)')
    p_clean.add_argument('-n', '--dry-run', action='store_true',
                         help='List what would be removed without deleting')

    # --- progress ---
    p_prog = sub.add_parser('progress', help='Report matching/in-progress function stats')
    p_prog.add_argument('dir', help='Project working directory')
    p_prog.add_argument('--single-binary', metavar='NAME',
                        help='Operate on only this binary')

    # --- compile (internal, called by Ninja) ---
    p_compile = sub.add_parser('compile', help='Compile source file (internal)')
    p_compile.add_argument('--source', required=True)
    p_compile.add_argument('--output', required=True)
    p_compile.add_argument('--cc', required=True, dest='cc_path')
    p_compile.add_argument('--flags', default='')

    # --- extract-compare (internal, called by Ninja) ---
    p_ec = sub.add_parser('extract-compare', help='Extract symbol and compare (internal)')
    p_ec.add_argument('--compiled', required=True)
    p_ec.add_argument('--split', required=True)
    p_ec.add_argument('--output', required=True)
    p_ec.add_argument('--sym', required=True)
    p_ec.add_argument('--symbols')
    p_ec.add_argument('--base-addr', type=lambda x: int(x, 0), default=0)
    p_ec.add_argument('--split-addr', type=lambda x: int(x, 0), default=0)

    # --- cro-from-elf (internal, called by Ninja) ---
    p_cro = sub.add_parser('cro-from-elf',
                           help='Flatten a linked ELF into a CRO module (internal)')
    p_cro.add_argument('--linked', required=True)
    p_cro.add_argument('--original', required=True)
    p_cro.add_argument('--output', required=True)
    p_cro.add_argument('--objcopy', required=True)

    # --- check-file (internal, called by Ninja) ---
    p_chkfile = sub.add_parser('check-file', help='Verify a single binary (internal)')
    p_chkfile.add_argument('--original', required=True)
    p_chkfile.add_argument('--built', required=True)

    args = parser.parse_args()

    match args.command:
        case 'split':
            from .config import ProjectConfig
            from .split import run_split
            config = ProjectConfig.load(Path(args.dir), args.single_binary)
            run_split(config, not args.no_progress)

        case 'ninja':
            from .config import ProjectConfig
            from .ninja import generate_ninja
            config = ProjectConfig.load(Path(args.dir), args.single_binary)
            generate_ninja(config)

        case 'objdiff':
            from .config import ProjectConfig
            from .objdiff import generate_objdiff
            config = ProjectConfig.load(Path(args.dir), args.single_binary)
            generate_objdiff(config)

        case 'build':
            from .build import run_build
            ok = run_build(Path(args.dir), args.jobs, args.keep_going, args.targets)
            sys.exit(0 if ok else 1)

        case 'check':
            from .config import ProjectConfig
            from .check import run_check
            config = ProjectConfig.load(Path(args.dir), args.single_binary)
            ok = run_check(config)
            sys.exit(0 if ok else 1)

        case 'clean':
            from .clean import run_clean
            ok = run_clean(Path(args.dir), args.targets, args.dry_run)
            sys.exit(0 if ok else 1)

        case 'progress':
            from .config import ProjectConfig
            from .objdiff import report_progress
            config = ProjectConfig.load(Path(args.dir), args.single_binary)
            report_progress(config)

        case 'compile':
            from .compare import compile_source
            flags = args.flags.split(',') if args.flags else []
            compile_source(
                source=Path(args.source),
                output=Path(args.output),
                cc=Path(args.cc_path),
                flags=flags,
            )

        case 'extract-compare':
            from .compare import extract_and_compare
            extract_and_compare(
                compiled=Path(args.compiled),
                split=Path(args.split),
                output=Path(args.output),
                sym=args.sym,
                symbols_csv=Path(args.symbols) if args.symbols else None,
                base_addr=args.base_addr,
                split_addr=args.split_addr,
            )

        case 'cro-from-elf':
            from .recreate import cro_from_elf
            cro_from_elf(Path(args.linked), Path(args.original),
                         Path(args.output), Path(args.objcopy))

        case 'check-file':
            from .check import check_binary
            ok = check_binary(Path(args.original), Path(args.built))
            sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
