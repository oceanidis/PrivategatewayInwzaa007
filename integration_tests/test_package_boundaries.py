from pathlib import Path
import tomllib


ROOT = Path(__file__).parents[1]


def load_project(package: str) -> dict:
    manifest = ROOT / 'packages' / package / 'pyproject.toml'
    with manifest.open('rb') as file:
        return tomllib.load(file)['project']


def dependency_name(dependency: str) -> str:
    return dependency.split('>', 1)[0].split('=', 1)[0].split('<', 1)[0].strip().lower()


def test_langchain_boundary_excludes_core_and_data_dependencies():
    dependencies = {
        dependency_name(dependency)
        for dependency in load_project('privategateway-langchain')['dependencies']
    }

    assert dependencies.isdisjoint({'privategateway', 'presidio-analyzer', 'pandas'})


def test_service_is_the_package_directly_depending_on_core():
    core_dependents = {
        package
        for package in (
            'privategateway-client',
            'privategateway-service',
            'privategateway-capabilities',
            'privategateway-langchain',
        )
        if any(
            dependency_name(dependency) == 'privategateway'
            for dependency in load_project(package)['dependencies']
        )
    }

    assert core_dependents == {'privategateway-service'}
