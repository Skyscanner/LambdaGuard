"""
Copyright 2020 Skyscanner Ltd

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.
"""
import json
from base64 import b64encode
from pathlib import Path


class HTMLReport:
    def __init__(self, path):
        self.path = Path(path)

    def txt2html(self, text):
        html = text.split('\n')
        return '<br>'.join(html)

    def save(self):
        '''
        Generates an HTML report
        '''
        assets_path = Path(__file__).parents[1].joinpath('assets')

        with assets_path.joinpath('index.html').open() as f:
            report_html = f.read()

        with assets_path.joinpath('logo.png').open('rb') as f:
            logo = b64encode(f.read()).decode('ascii')
            report_html = report_html.replace('{logo}', str(logo))

        # ===================================================== Statistics
        if not self.path.joinpath('statistics.json').exists():
            return
        with self.path.joinpath('statistics.json').open() as f:
            stats_json = json.loads(f.read())

        exclude_info = stats_json['lambdas'] > 1  # Exclude info level

        stats_table = assets_path.joinpath('stats.html').open().read()
        stats_table_item = assets_path.joinpath('statsitem.html').open().read()
        for title, data in stats_json.items():
            if title in ['lambdas', 'regions', 'layers']:
                continue

            if exclude_info and title == 'security':
                count = data['count'] - data['items']['info']
            else:
                count = data['count']
            stats_table = stats_table.replace('{' + title + '_count}', str(count))

            stats_items = []
            for name, count in data['items'].items():
                if exclude_info and name == 'info':
                    continue
                stats_items.append(
                    stats_table_item.replace('{name}', name).replace('{count}', str(count))
                )
            stats_table = stats_table.replace('{' + title + '_items}', ''.join(stats_items))
        stats_table = stats_table.replace('{lambdas_count}', str(stats_json['lambdas']))
        stats_table = stats_table.replace('{layers_count}', str(stats_json['layers']))

        with assets_path.joinpath('highcharts.js').open() as f:
            report_html = report_html.replace('{highcharts}', f.read())
        with assets_path.joinpath('highcharts-theme.js').open() as f:
            report_html = report_html.replace('{highcharts-theme}', f.read())

        with assets_path.joinpath('stats.js').open() as f:
            stats_template = f.read()

        stats_js = []
        for title, data in stats_json.items():
            if title in ['lambdas', 'regions', 'layers']:
                continue

            series = []
            for name, y in data['items'].items():
                if exclude_info and name == 'info':
                    data['count'] -= y
                    continue
                series.append({'name': name, 'y': y})

            chart = stats_template
            chart = chart.replace('{chartid}', f'stats-{title}')
            chart = chart.replace('{title}', f'{title} ({data["count"]})')
            chart = chart.replace('{count}', str(data['count']))
            chart = chart.replace('{data}', json.dumps(series))
            stats_js.append(chart)

        report_html = report_html.replace('{statistics}', stats_table)
        report_html = report_html.replace('{highcharts-data}', '\n'.join(stats_js))

        stats_table = None
        stats_js = None

        # ===================================================== Security
        with self.path.joinpath('security.json').open() as f:
            vulns_json = json.loads(f.read())

        with assets_path.joinpath('vuln.html').open() as f:
            vuln_html_template = f.read()

        vulns_html = ''
        for _ in vulns_json:
            if exclude_info and _['level'] == 'info':
                continue
            html = vuln_html_template
            html = html.replace('{index}', _['index'])
            html = html.replace('{level}', _['level'])
            html = html.replace('{text}', self.txt2html(_['text']))
            html = html.replace('{where}', self.txt2html(_['where']))
            html = html.replace('{lambda}', _['lambda'])
            vulns_html += f'{html}\n'

        with assets_path.joinpath('vulnlist.html').open() as f:
            vulnlist_html = f.read()

        vulnlist_html = vulnlist_html.replace('{items}', vulns_html)

        report_html = report_html.replace('{security}', vulnlist_html)

        vulns_json = None
        vulns_html = None
        vulnlist_html = None

        # ===================================================== Functions & Layers
        all_layers = []

        with self.path.joinpath('index.json').open() as f:
            index = json.loads(f.read())

        with assets_path.joinpath('func.html').open() as f:
            func_html_template = f.read()

        with assets_path.joinpath('funcvuln.html').open() as f:
            vuln_html_template = f.read()

        funcs_html = ''

        for idx in index.keys():
            with self.path.joinpath('reports', f'{idx}.json').open() as f:
                func = json.loads(f.read())

            funcvuln_html = []

            for _ in func['security']['items']:
                if exclude_info and _['level'] == 'info':
                    continue
                ret = vuln_html_template.replace('{where}', self.txt2html(_['where']))
                ret = ret.replace('{level}', _['level'])
                ret = ret.replace('{text}', self.txt2html(_['text']))
                funcvuln_html.append(ret)

            layers = []
            for layer in func['layers']:
                layers.append(f"{layer['arn']} ({layer['description']})")
                layer.update({'runtime': func['runtime']})
                if layer not in all_layers:
                    all_layers.append(layer)

            html = func_html_template
            html = html.replace('{index}', idx)
            html = html.replace('{arn}', func['arn'])
            html = html.replace('{name}', func['name'])
            html = html.replace('{description}', func['description'])
            html = html.replace('{region}', func['region'])
            html = html.replace('{runtime}', func['runtime'])
            html = html.replace('{handler}', func['handler'])
            html = html.replace('{role}', func['role'])
            html = html.replace('{layers}', self.txt2html('\n'.join(layers)))
            html = html.replace('{layers_count}', str(len(func['layers'])))
            html = html.replace('{triggers}', self.txt2html(', '.join(func['triggers']['services'])))
            html = html.replace('{triggers_count}', str(len(func['triggers']['services'])))
            html = html.replace('{resources}', self.txt2html(', '.join(func['resources']['services'])))
            html = html.replace('{resources_count}', str(len(func['resources']['services'])))
            html = html.replace('{security}', ''.join(funcvuln_html))
            html = html.replace('{security_count}', str(len(funcvuln_html)))
            html = html.replace('{policy}', json.dumps(func['policy']['function'], indent=4))
            html = html.replace('{role_policy}', json.dumps(func['policy']['role'], indent=4))
            if 'kms' in func:
                html = html.replace('{kms}', func['kms'])
                html = html.replace('{kms_policies}', json.dumps(func['policy']['kms'], indent=4))
            else:
                html = html.replace('{kms}', '')
                html = html.replace('{kms_policies}', '{}')

            funcs_html += f'{html}\n'

        with assets_path.joinpath('funclist.html').open() as f:
            funclist_html = f.read()

        funclist_html = funclist_html.replace('{items}', funcs_html)

        report_html = report_html.replace('{functions}', funclist_html)

        funcs_html = None
        funclist_html = None

        with assets_path.joinpath('layer.html').open() as f:
            layer_html_template = f.read()

        layer_html = ''

        for layer in all_layers:
            html = layer_html_template.replace('{arn}', layer['arn'])
            html = html.replace('{description}', layer['description'])
            html = html.replace('{runtime}', layer['runtime'])
            layer_html += f'{html}\n'

        with assets_path.joinpath('layerlist.html').open() as f:
            layerlist_html = f.read()

        layerlist_html = layerlist_html.replace('{items}', layer_html)

        report_html = report_html.replace('{layers}', layerlist_html)

        layer_html = None
        layerlist_html = None

        # ===================================================== HTML

        with self.path.joinpath('report.html').open('w') as f:
            f.write(report_html)
