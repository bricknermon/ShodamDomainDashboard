import dash
import dash_core_components as dcc
import dash_html_components as html
from dash.dependencies import Input, Output
import dash_bootstrap_components as dbc
import sqlite3
import pandas as pd
import dash_table
import numpy as np
import plotly.graph_objs as go

app = dash.Dash(__name__, external_stylesheets=[dbc.themes.BOOTSTRAP])
server = app.server


def get_data():
    conn = sqlite3.connect("scan_data.db")
    query = """
    SELECT d.domain_name, d.scan_date, dd.subdomain, dd.address, dd.open_ports, dd.vulnerabilities 
    FROM domains d
    INNER JOIN domain_data dd ON d.id = dd.domain_id
    ORDER BY d.scan_date DESC
    """
    df = pd.read_sql(query, conn)
    conn.close()
    return df


def generate_graphs(df):
    # Line Chart for Trend
    subdomain_counts = df.groupby("scan_date").subdomain.nunique().reset_index()
    subdomain_chart = dcc.Graph(
        figure={
            "data": [
                {
                    "x": subdomain_counts["scan_date"],
                    "y": subdomain_counts["subdomain"],
                    "type": "line",
                    "name": "Subdomains",
                },
            ],
            "layout": {"title": "Subdomain Trend Over Time"},
        }
    )

    # Line Chart for Trend
    domain_counts = df.groupby("scan_date").domain_name.nunique().reset_index()
    domain_chart = dcc.Graph(
        figure={
            "data": [
                {
                    "x": domain_counts["scan_date"],
                    "y": domain_counts["domain_name"],
                    "type": "line",
                    "name": "Domains",
                },
            ],
            "layout": {"title": "Domain Trend Over Time"},
        }
    )

    # Total Number of Subdomains
    total_subdomains = df["subdomain"].nunique()
    total_subdomains_card = dbc.Card(
        [
            dbc.CardBody(
                [
                    html.H4("Total Subdomains", className="card-title"),
                    html.P(total_subdomains, className="card-text"),
                ]
            )
        ]
    )

    # Total Number of Domains
    total_domains = df["domain_name"].nunique()
    total_domains_card = dbc.Card(
        [
            dbc.CardBody(
                [
                    html.H4("Total Domains", className="card-title"),
                    html.P(total_domains, className="card-text"),
                ]
            )
        ]
    )

    # Total Number of Domains
    total_ports = df["open_ports"].nunique()
    total_ports_card = dbc.Card(
        [
            dbc.CardBody(
                [
                    html.H4("Total Ports", className="card-title"),
                    html.P(total_ports, className="card-text"),
                ]
            )
        ]
    )

    # Convert 'vulnerabilities' from string to list
    total_vulns = df["vulnerabilities"].nunique()
    total_vulns_card = dbc.Card(
        [
            dbc.CardBody(
                [
                    html.H4("Total vulns", className="card-title"),
                    html.P(total_vulns, className="card-text"),
                ]
            )
        ]
    )

    total_ips = df["address"].nunique()
    total_ips_card = dbc.Card(
        [
            dbc.CardBody(
                [
                    html.H4("Total IPs", className="card-title"),
                    html.P(total_ips, className="card-text"),
                ]
            )
        ]
    )

    # Table for Data
    table = dash_table.DataTable(
        id='datatable-interactivity',
        columns=[
        {"name": i, "id": i, "deletable": False, "selectable": True} 
        for i in get_data().columns
    ],
        data=get_data().to_dict('records'),
        editable=False,
        filter_action="native",
        sort_action="native",  # Enable sorting
        sort_mode="multi",  # Allow multiple columns to be sorted
        page_action="native",  # Enable pagination
        page_current=0,  # Start at the first page
        page_size=20,  # Set the number of rows per page
        filter_options=generate_filter_options(get_data()),  # Generate filter options for each column
)

    ip_counts = df.groupby("scan_date").address.nunique().reset_index()
    ip_chart = dcc.Graph(
        figure={
            "data": [
                {
                    "x": ip_counts["scan_date"],
                    "y": ip_counts["address"],
                    "type": "line",
                    "name": "IP Addresses",
                },
            ],
            "layout": {"title": "IP Address Trend Over Time"},
        }
    )

    # Convert 'open_ports' from string to list of integers
    df["open_ports_list"] = (
        df["open_ports"]
        .str.split(", ")
        .apply(lambda x: [int(port) for port in x if port.isdigit()])
    )

    # Count unique ports for each scan date
    port_counts = (
        df.explode("open_ports_list")
        .groupby("scan_date")
        .open_ports_list.nunique()
        .reset_index()
    )
    ports_chart = dcc.Graph(
        figure={
            "data": [
                {
                    "x": port_counts["scan_date"],
                    "y": port_counts["open_ports_list"],
                    "type": "line",
                    "name": "Unique Open Ports",
                },
            ],
            "layout": {"title": "Unique Open Ports Trend Over Time"},
        }
    )

    # Convert 'vulnerabilities' from string to list
    df["vuln_list"] = df["vulnerabilities"].str.split(", ")

    # Count unique vulnerabilities for each scan date
    vuln_counts = (
        df.explode("vuln_list")
        .groupby("scan_date")
        .vuln_list.nunique()
        .reset_index()
    )
    vuln_chart = dcc.Graph(
        figure={
            "data": [
                {
                    "x": vuln_counts["scan_date"],
                    "y": vuln_counts["vuln_list"],
                    "type": "line",
                    "name": "Unique Vulnerabilities",
                },
            ],
            "layout": {"title": "Unique Vulnerabilities Trend Over Time"},
        }
    )
    data = df.to_dict('records')
    return (
        data,
        table,
        domain_chart,
        subdomain_chart,
        ip_chart,
        ports_chart,
        vuln_chart,
        total_domains_card,
        total_subdomains_card,
        total_ips_card,
        total_vulns_card,
        total_ports_card,
    )

def generate_filter_options(dataframe):
    filter_options = {}
    for column in dataframe.columns:
        filter_options[column] = [{'label': str(value), 'value': str(value)} for value in dataframe[column].unique()]
    return filter_options


app.layout = html.Div(
    [
        dbc.Row(
            dbc.Col(html.H1("Domain Scan Dashboard"), width={"size": 6, "offset": 3}),
            className="mb-4",
        ),
        dbc.Row(
            dbc.Col(
                dcc.Dropdown(
                    id="domain-dropdown",
                    options=[
                        {"label": domain, "value": domain}
                        for domain in get_data()["domain_name"].unique()
                    ],
                    value="All Domains",  # Default value
                    clearable=False,
                    searchable=True,  # Add search functionality
                ),
                width=6,
            ),
            className="mb-4",
        ),
        dbc.Row(
            [
                dbc.Col(html.Div(id="total-domains-card"), width=2),
                dbc.Col(html.Div(id="total-subdomains-card"), width=2),
                dbc.Col(html.Div(id="total-ips-card"), width=2),
                dbc.Col(html.Div(id="total-vulns-card"), width=2),
                dbc.Col(html.Div(id="total-ports-card"), width=2),
            ]
        ),
        dbc.Row(
            [
                dbc.Col(html.Div(id="domain-trend"), width=4),
                dbc.Col(html.Div(id="subdomain-trend"), width=4),
                dbc.Col(html.Div(id="ip-trend"), width=4),
            ]
        ),
        dbc.Row(
            [
                dbc.Col(html.Div(id="vulnerability-trend"), width=4),
                dbc.Col(html.Div(id="ports-trend"), width=4),
            ]
        ),
        dbc.Row(
            dbc.Col(
                dash_table.DataTable(
                    id='datatable-interactivity',
                    columns=[
                        {"name": i, "id": i, "deletable": False, "selectable": True} 
                        for i in get_data().columns
                    ],
                    data=get_data().to_dict('records'),
                    editable=False,
                    sort_action="native",  # Enable sorting
                    sort_mode="multi",  # Allow multiple columns to be sorted
                    page_action="native",  # Enable pagination
                    page_current=0,  # Start at the first page
                    page_size=25,  # Set the number of rows per page
                    filter_action="native",  # Enable native filtering
                    filter_options=generate_filter_options(get_data()),  # Generate filter options for each column
                ),
                width=12
            )
        ),
    ]
)







@app.callback(
    [
        Output("datatable-interactivity", "data"),
        Output("domain-trend", "children"),
        Output("subdomain-trend", "children"),
        Output("ip-trend", "children"),
        Output("ports-trend", "children"),
        Output("vulnerability-trend", "children"),
        Output("total-domains-card","children"),
        Output("total-subdomains-card", "children"),
        Output("total-ips-card", "children"),
        Output("total-vulns-card", "children"),
        Output("total-ports-card", "children"),
    ],
    [Input("domain-dropdown", "value")],
)
def update_output(value):
    df = get_data()

    if value != "All Domains":
        filtered_df = df[df["domain_name"] == value]
    else:
        filtered_df = df

    # Generate DataTable data
    table_data = filtered_df.to_dict("records")

    # Generate domain trend graph
    domain_counts = (
        filtered_df.groupby("scan_date").domain_name.nunique().reset_index()
    )
    domain_chart = dcc.Graph(
        figure={
            "data": [
                {
                    "x": domain_counts["scan_date"],
                    "y": domain_counts["domain_name"],
                    "type": "line",
                    "name": "Domains",
                },
            ],
            "layout": {"title": "Domain Trend Over Time"},
        }
    )

    # Generate subdomain trend graph
    subdomain_counts = (
        filtered_df.groupby("scan_date").subdomain.nunique().reset_index()
    )
    subdomain_chart = dcc.Graph(
        figure={
            "data": [
                {
                    "x": subdomain_counts["scan_date"],
                    "y": subdomain_counts["subdomain"],
                    "type": "line",
                    "name": "Subdomains",
                },
            ],
            "layout": {"title": "Subdomain Trend Over Time"},
        }
    )

    # Generate IP trend graph
    ip_counts = filtered_df.groupby("scan_date").address.nunique().reset_index()
    ip_chart = dcc.Graph(
        figure={
            "data": [
                {
                    "x": ip_counts["scan_date"],
                    "y": ip_counts["address"],
                    "type": "line",
                    "name": "IP Addresses",
                },
            ],
            "layout": {"title": "IP Address Trend Over Time"},
        }
    )

    # Generate ports trend graph
    filtered_df["open_ports_list"] = (
        filtered_df["open_ports"]
        .str.split(", ")
        .apply(lambda x: [int(port) for port in x if port.isdigit()])
    )
    port_counts = (
        filtered_df.explode("open_ports_list")
        .groupby("scan_date")
        .open_ports_list.nunique()
        .reset_index()
    )
    ports_chart = dcc.Graph(
        figure={
            "data": [
                {
                    "x": port_counts["scan_date"],
                    "y": port_counts["open_ports_list"],
                    "type": "line",
                    "name": "Unique Open Ports",
                },
            ],
            "layout": {"title": "Unique Open Ports Trend Over Time"},
        }
    )

    # Generate vulnerability trend graph
    filtered_df["vuln_list"] = filtered_df["vulnerabilities"].str.split(", ")
    vuln_counts = (
        filtered_df.explode("vuln_list")
        .groupby("scan_date")
        .vuln_list.nunique()
        .reset_index()
    )
    vuln_chart = dcc.Graph(
        figure={
            "data": [
                {
                    "x": vuln_counts["scan_date"],
                    "y": vuln_counts["vuln_list"],
                    "type": "line",
                    "name": "Unique Vulnerabilities",
                },
            ],
            "layout": {"title": "Unique Vulnerabilities Trend Over Time"},
        }
    )

    # Generate total domains card
    total_domains_card = dbc.Card(
        [
            dbc.CardBody(
                [
                    html.H4("Total Domains", className="card-title"),
                    html.P(len(filtered_df["domain_name"].unique()), className="card-text"),
                ]
            )
        ]
    )

    # Generate total subdomains card
    total_subdomains_card = dbc.Card(
        [
            dbc.CardBody(
                [
                    html.H4("Total Subdomains", className="card-title"),
                    html.P(filtered_df["subdomain"].nunique(), className="card-text"),
                ]
            )
        ]
    )

    # Generate total IPs card
    total_ips_card = dbc.Card(
        [
            dbc.CardBody(
                [
                    html.H4("Total IPs", className="card-title"),
                    html.P(filtered_df["address"].nunique(), className="card-text"),
                ]
            )
        ]
    )

    # Generate total vulnerabilities card
    total_vulns_card = dbc.Card(
        [
            dbc.CardBody(
                [
                    html.H4("Total Vulnerabilities", className="card-title"),
                    html.P(filtered_df["vulnerabilities"].nunique(), className="card-text"),
                ]
            )
        ]
    )

    # Generate total ports card
    total_ports_card = dbc.Card(
        [
            dbc.CardBody(
                [
                    html.H4("Total Open Ports", className="card-title"),
                    html.P(filtered_df["open_ports"].nunique(), className="card-text"),
                ]
            )
        ]
    )

    return (
        table_data,
        domain_chart,
        subdomain_chart,
        ip_chart,
        ports_chart,
        vuln_chart,
        total_domains_card,
        total_subdomains_card,
        total_ips_card,
        total_vulns_card,
        total_ports_card,
    )


if __name__ == '__main__':
    app.run_server(debug=True)
