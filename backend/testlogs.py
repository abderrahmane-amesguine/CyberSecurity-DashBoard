import json
import csv
from datetime import datetime
from drain3 import TemplateMiner

# Create template miner
template_miner = TemplateMiner()

def process_log_file(template_miner, log_file):
    """Process the log file and feed data to Drain3"""
    processed_count = 0
    
    try:
        print(f"📁 Processing log file: {log_file}")
        
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if line:  # Skip empty lines
                    try:
                        # THIS IS THE KEY STEP YOU WERE MISSING
                        result = template_miner.add_log_message(line)
                        processed_count += 1
                        
                        # Print progress every 500 lines
                        if processed_count % 500 == 0:
                            print(f"  Processed {processed_count} lines...")
                        
                        # Print first few results for debugging
                        if processed_count <= 3:
                            print(f"  Sample {processed_count}:")
                            print(f"    Original: {line}")
                            print(f"    Template: {result['template_mined']}")
                            print(f"    Cluster ID: {result['cluster_id']}")
                            print()
                            
                    except Exception as e:
                        print(f"    Error on line {line_num}: {e}")
                        continue
        
        print(f"✅ Successfully processed {processed_count} log lines")
        print(f" Found {len(template_miner.drain.clusters)} unique templates")
        
        return processed_count
        
    except FileNotFoundError:
        print(f"❌ Error: File '{log_file}' not found!")
        return 0
    except Exception as e:
        print(f"❌ Error reading file: {e}")
        return 0

def export_drain3_results(template_miner, log_file, output_format='json'):
    # Collect all data
    export_data = {
        'analysis_timestamp': datetime.now().isoformat(),
        'source_file': log_file,
        'total_clusters': len(template_miner.drain.clusters),
        'clusters': []
    }
    
    # Extract cluster data
    for cluster in template_miner.drain.clusters:
        cluster_data = {
            'cluster_id': cluster.cluster_id,
            'template': cluster.get_template(),
            'size': cluster.size,
            'tokens': cluster.log_template_tokens
        }
        export_data['clusters'].append(cluster_data)
    
    # Export based on format
    if output_format == 'json':
        with open('drain3_results.json', 'w') as f:
            json.dump(export_data, f, indent=2)
        print(f"📄 Created: drain3_results.json")
    
    elif output_format == 'csv':
        with open('drain3_results.csv', 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Cluster_ID', 'Template', 'Frequency', 'Tokens'])
            
            for cluster in export_data['clusters']:
                writer.writerow([
                    cluster['cluster_id'],
                    cluster['template'],
                    cluster['size'],
                    ' | '.join(cluster['tokens'])
                ])
        print(f"📄 Created: drain3_results.csv")
    
    return export_data

def show_template_summary(template_miner):
    """Show a summary of discovered templates"""
    clusters = template_miner.drain.clusters
    
    if not clusters:
        print("No templates found!")
        return
    
    # Sort by frequency (most common first)
    sorted_clusters = sorted(clusters, key=lambda c: c.size, reverse=True)
    
    print(f"\n📊 Template Summary:")
    print(f"Total unique templates: {len(clusters)}")
    
    print(f"\n Top 10 Most Frequent Templates:")
    for i, cluster in enumerate(sorted_clusters[:10], 1):
        print(f"{i:2d}. ({cluster.size:4d}x) {cluster.get_template()}")

# MAIN EXECUTION
if __name__ == "__main__":
    log_file = 'cisco_asa_test.log'
    
    print(" Starting Drain3 log analysis...")
    
    # Step 1: Process the log file (THIS WAS MISSING!)
    lines_processed = process_log_file(template_miner, log_file)
    
    if lines_processed > 0:
        # Step 2: Show summary
        show_template_summary(template_miner)
        
        # Step 3: Export results
        print(f"\n💾 Exporting results...")
        exported_data = export_drain3_results(template_miner, log_file, 'json')
        export_drain3_results(template_miner, log_file, 'csv')  # Also create CSV
        
        print(f"✅ Exported {len(exported_data['clusters'])} templates")
    else:
        print("❌ No data processed. Check if the log file exists and has content.")