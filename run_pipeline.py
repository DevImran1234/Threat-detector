#!/usr/bin/env python3
"""
MITRE Security Pipeline - Simple Runner
Usage: python run_pipeline.py --log "log message here"
"""

import sys
import os
import argparse
import json
from datetime import datetime

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from main_orchestrator import MITREOrchestrator
from utils import setup_logging

def main():
    parser = argparse.ArgumentParser(description='MITRE Security Pipeline')
    parser.add_argument('--log', type=str, help='Single log message to process')
    parser.add_argument('--file', type=str, help='File containing logs (one per line)')
    parser.add_argument('--config', type=str, default='config.yaml', help='Configuration file')
    parser.add_argument('--output', type=str, default='output/results.json', help='Output file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Setup logging
    logger = setup_logging(__name__, verbose=args.verbose)
    
    # Initialize orchestrator
    logger.info("🚀 Initializing MITRE Security Pipeline...")
    orchestrator = MITREOrchestrator(config_file=args.config)
    
    results = []
    
    if args.log:
        # Process single log
        logger.info(f"Processing single log: {args.log[:100]}...")
        result = orchestrator.process_single_log(args.log)
        results.append(result)
        
        # Print summary
        print("\n" + "="*70)
        print("MITRE SECURITY PIPELINE - RESULT")
        print("="*70)
        print(f"Log: {args.log[:200]}...")
        print(f"\nClassification: {result['agent1']['label']} "
              f"(Confidence: {result['agent1']['confidence']:.2%})")
        
        if result['mitre']['mitre_techniques']:
            print("\nMITRE Techniques Detected:")
            for tech in result['mitre']['mitre_techniques']:
                print(f"  • {tech['technique_id']}: {tech['name']} "
                      f"(Confidence: {tech['confidence']:.2%})")
        else:
            print("\nNo MITRE techniques detected")
        
        print(f"\nRisk Score: {result['mitre']['risk_score']:.1f}/100")
        print(f"Primary Tactic: {result['mitre']['primary_tactic']}")
        
        if result['agent2']['actions']:
            print(f"\nResponse Actions:")
            for action in result['agent2']['actions']:
                print(f"  • {action}")
        else:
            print("\nNo response actions required")
        
        print("="*70)
        
    elif args.file:
        # Process log file
        if not os.path.exists(args.file):
            logger.error(f"File not found: {args.file}")
            return
            
        logger.info(f"Processing log file: {args.file}")
        with open(args.file, 'r') as f:
            logs = [line.strip() for line in f if line.strip()]
        
        for i, log in enumerate(logs, 1):
            logger.info(f"Processing log {i}/{len(logs)}")
            try:
                result = orchestrator.process_single_log(log)
                results.append(result)
            except Exception as e:
                logger.error(f"Error processing log {i}: {e}")
                continue
        
        print(f"\n✅ Processed {len(results)} logs from {args.file}")
        
    else:
        # Interactive mode
        print("\nMITRE Security Pipeline - Interactive Mode")
        print("Enter logs to analyze (type 'exit' to quit, 'help' for commands)")
        print("-" * 50)
        
        while True:
            try:
                log = input("\n🔍 Enter log: ").strip()
                
                if not log:
                    continue
                if log.lower() == 'exit':
                    break
                if log.lower() == 'help':
                    print("\nCommands:")
                    print("  exit  - Exit the program")
                    print("  help  - Show this help")
                    print("  stats - Show pipeline statistics")
                    continue
                if log.lower() == 'stats':
                    stats = orchestrator.get_statistics()
                    print(f"\n📊 Pipeline Statistics:")
                    print(f"  Total logs processed: {stats.get('total_processed', 0)}")
                    print(f"  Average processing time: {stats.get('avg_time', 0):.2f}s")
                    print(f"  MITRE detections: {stats.get('mitre_detections', 0)}")
                    continue
                
                result = orchestrator.process_single_log(log)
                results.append(result)
                
                # Quick summary
                techs = result['mitre_mapping']['mitre_techniques']
                if techs:
                    print(f"  → MITRE: {techs[0]['technique_id']} "
                          f"(Risk: {result['mitre_mapping']['risk_score']:.0f}/100)")
                else:
                    print(f"  → No MITRE techniques detected")
                
                actions = result['response']['actions']
                if actions:
                    print(f"  → Action: {actions[0]}")
                
            except KeyboardInterrupt:
                print("\n\nExiting...")
                break
            except Exception as e:
                print(f"  ❌ Error: {e}")
    
    # Save results
    if results:
        os.makedirs(os.path.dirname(args.output) or '.', exist_ok=True)
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        logger.info(f"Results saved to {args.output}")
    
    logger.info("Pipeline execution completed")

if __name__ == "__main__":
    main()