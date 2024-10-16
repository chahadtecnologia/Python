import json

# Function to generate the report in HTML
def generate_html_report(json_file, output_html):
    with open(json_file, 'r') as f:
        data = json.load(f)
    
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Network Scan Report</title>
        <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;700&display=swap" rel="stylesheet">
        <style>
            body {{
                font-family: 'Roboto', sans-serif;
                background-color: #f4f4f9;
                margin: 0;
                padding: 20px;
                color: #333;
            }}
            h1 {{
                text-align: center;
                color: #2c3e50;
                font-weight: 700;
                margin-bottom: 40px;
            }}
            .host {{
                background-color: #fff;
                padding: 20px;
                margin-bottom: 20px;
                box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
                border-radius: 8px;
            }}
            .host h2 {{
                color: #34495e;
                border-bottom: 2px solid #bdc3c7;
                padding-bottom: 10px;
            }}
            .service {{
                margin-left: 20px;
                margin-top: 10px;
            }}
            .service p {{
                margin: 5px 0;
            }}
            .vuln {{
                color: #e74c3c;
                font-weight: bold;
            }}
            .no-vuln {{
                color: #2ecc71;
                font-weight: bold;
            }}
        </style>
    </head>
    <body>
        <h1>Final Report</h1>
    """

    # Generate content for each host and its services
    for host, protocols in data.items():
        html_content += f"""
        <div class="host">
            <h2>Host: {host}</h2>
        """
        
        for protocol, services in protocols.items():
            for service in services:
                port = service['port']
                proto = service['protocol']
                name = service['service']
                state = service['state']
                product = service.get('product', 'Unknown')
                version = service.get('version', 'Unknown')
                vulnerabilities = service.get('vulnerabilities', 'No vulnerabilities found')

                html_content += f"""
                <div class="service">
                    <p><strong>Port:</strong> {port}/{proto}</p>
                    <p><strong>Service:</strong> {name}</p>
                    <p><strong>State:</strong> {state}</p>
                    <p><strong>Product:</strong> {product}</p>
                    <p><strong>Version:</strong> {version}</p>
                """
                
                if vulnerabilities != "No vulnerabilities found":
                    html_content += f"<p class='vuln'>Vulnerabilities: {vulnerabilities}</p>"
                else:
                    html_content += f"<p class='no-vuln'>No vulnerabilities found</p>"

                html_content += "</div>"

        html_content += "</div>"

    html_content += """
    </body>
    </html>
    """

    # Save content to HTML file
    with open(output_html, 'w') as f:
        f.write(html_content)

    print(f"HTML report generated: {output_html}")
