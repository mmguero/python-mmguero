"""Command-line entry point (the `mmguero` console script)."""

import sys

try:
    import fire
except Exception:
    fire = None

import importlib.metadata
import inspect

from .clihints import _exclude_from_cli


@_exclude_from_cli
def main():
    """Entry point for running this module as a script."""

    if (fire is not None) and (len(sys.argv) > 1):
        import mmguero  # deferred on purpose

        commands = {
            name: obj
            for name in mmguero.__all__
            if inspect.isfunction(obj := getattr(mmguero, name)) and not getattr(obj, "_mmguero_no_cli", False)
        }
        fire.Fire(commands)

    else:

        package_name = __package__ or "mmguero"

        try:
            metadata = importlib.metadata.metadata(package_name)
            version = metadata.get("Version", "unknown")
            summary = metadata.get("Summary", "")

            # Extract all project URLs (Hatchling puts them here)
            project_urls = []
            for key, value in metadata.items():
                if key.lower() == "project-url":
                    project_urls.append(value)

        except importlib.metadata.PackageNotFoundError:
            version = "source"
            summary = "Seth Grover's useful Python helpers (uninstalled source tree)"
            project_urls = []

        print(f"\n🧰 {package_name} v{version}")
        if summary:
            print(f"   {summary}")

        if project_urls:
            print("\n🌐 Project URLs:")
            for entry in project_urls:
                print(f"   {entry}")

        print("\n📦 Public functions and classes:")

        module = sys.modules[package_name]
        public_items = []

        for name in getattr(module, "__all__", []):
            obj = getattr(module, name, None)
            if inspect.isfunction(obj):
                public_items.append(f"  ⚙️  {name}()")
            elif inspect.isclass(obj):
                public_items.append(f"  🧱 {name}")
            else:
                public_items.append(f"  🔹 {name}")

        if public_items:
            print("\n".join(public_items))
        else:
            print("  (none found)")
        print()

        sys.exit(0)
