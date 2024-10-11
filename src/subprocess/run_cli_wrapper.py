import subprocess
import getpass
import argparse
import sys

def run_command(command, args):
    password = getpass.getpass("Enter password: ")
    
    full_command = [command] + args
    
    try:
        process = subprocess.Popen(full_command, 
                                   stdin=subprocess.PIPE, 
                                   stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE, 
                                   text=True)
        
        stdout, stderr = process.communicate(input=password + '\n')
        
        if process.returncode != 0:
            print(f"Error: {stderr}")
            sys.exit(1)
        
        print(stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Run CLI wrapper securely")
    parser.add_argument('command', help="Path to the Rust binary")
    parser.add_argument('args', nargs=argparse.REMAINDER, help="Arguments for the Rust binary")
    
    args = parser.parse_args()
    
    run_command(args.command, args.args)

if __name__ == "__main__":
    main()