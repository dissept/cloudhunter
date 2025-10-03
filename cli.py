import click

@click.group()
def cli():
    """Cloudhunter CLI — run scans and export findings."""

@cli.command()
@click.option("--provider", type=click.Choice(["aws", "azure", "gcp"]), required=True)
def scan(provider):
    """Mock scan (placeholder)."""
    click.echo(f"Running scan for {provider}...")
    # TODO: call engine.shared_logic

@cli.command()
def version():
    click.echo("Cloudhunter CLI 0.1.0")

if __name__ == "__main__":
    cli()
