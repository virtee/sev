# SPDX-License-Identifier: Apache-2.0

'''
Tool to handle the allocation of guest network ports to multiple SNP guest without network port conflict, and
to cleanup the inactive guest network port in the GH Action Workflow Guest n/w Port inventory file

Pre-requisite for this tool use:
    Set DOTENV_PATH(environment variable) on the host with the .env file path having GHAW_GUEST_PORT_FILE
'''

import subprocess
import argparse
from dotenv import load_dotenv
import os

# Gets GHAW guest port file location
dotenv_path = os.path.join(os.path.dirname(__file__), os.getenv("DOTENV_PATH"))
load_dotenv(dotenv_path)

ghaw_taken_ports_file = os.getenv("GHAW_GUEST_PORT_FILE")
if not ghaw_taken_ports_file:
    print("Set DOTENV_PATH(environment variable) on host with the .env file path having GHAW_GUEST_PORT_FILE!")
    exit()

def execute_bash_command(command):
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout.strip()

def read_ports_from_file(filename):
  ports_in_use = []
  with open(filename, 'r') as file:
    for line in file:
      ports_in_use.append(line.strip())
  return ports_in_use

def get_next_available_port(starting_port, ending_port):
    '''
    Returns the unused network port from the network port range to run multiple SNP guest without port conflicts
    '''

    # Reads the guest port in use by GH Action workflow
    ghaw_taken_ports = read_ports_from_file(ghaw_taken_ports_file)
    ghaw_taken_ports = list(map(int, ghaw_taken_ports))

    # Assumption: All n/w ports are used up
    all_ports_used=1
    port_to_use=-1

    for port_number in range(starting_port, ending_port+1):
        port_status=f"sudo netstat -plnt | grep ':{port_number}'"
        running_guest_port= execute_bash_command(port_status)

        # Assigns unused n/w port number
        if not running_guest_port and port_number not in ghaw_taken_ports:
            port_to_use=port_number
            all_ports_used=0

            # Notes unused n/w port to avoid port conflicts in GHAW
            with open(ghaw_taken_ports_file, "a") as file:
                    file.write(str(port_to_use)+"\n")
            break

    if all_ports_used == 0:
        print(port_number)
    else:
        print("No network port is available!")
        print("\n All ports in a given network range are taken up!")

def remove_ghaw_used_ports(ghaw_port_number):
    '''
    Removes the used guest port after SNP Guest test is completed for the cleanup GHAW process
    '''
    try:
        with open(ghaw_taken_ports_file, 'r') as fr:
            lines = fr.readlines()
            flag_ghaw_port_number=0
            with open(ghaw_taken_ports_file, 'w') as fw:
                for line in lines:
                    if line.strip('\n') != str(ghaw_port_number):
                        fw.write(line)
                    else:
                        flag_ghaw_port_number=1

        if flag_ghaw_port_number == 1:
            print(f"Guest network port {ghaw_port_number} is removed from GH Action Workflow use!")
        else:
            print(f"Guest network port {ghaw_port_number} is not in use by GH Action Workflow!")
    except:
        print("GH Action guest ports inventory file not found on the host!")

def main():
    parser = argparse.ArgumentParser(description='Tool to handle SNP Guest network port allocation for the network port range')
    subparsers = parser.add_subparsers(dest='command')

    # Command 1: Allocates unused port number between the network port range for the SNP guest port allocation
    parser_1 = subparsers.add_parser('get-next-available-port-number', help='Get the next available port to use for the given network port range')
    parser_1.add_argument('--starting_port', type=int, help='Starting port number of the network port range', default=49152)
    parser_1.add_argument('--ending_port', type=int, help='Ending port number fof the network port range', default=65535)
    parser_1.set_defaults(func=get_next_available_port)

    # Command 2: Removes used guest port as a GH Action SNP guest cleanup process
    parser_2 = subparsers.add_parser('remove-ghaw-used-port-number', help='Remove the ports in use by GH action workflow')
    parser_2.add_argument('ghaw_port_number', type=int, help='Port number in use by GH Action workflow')
    parser_2.set_defaults(func=remove_ghaw_used_ports)

    args = parser.parse_args()

    if args.command == 'get-next-available-port-number':
        get_next_available_port(args.starting_port, args.ending_port)
    elif args.command == 'remove-ghaw-used-port-number':
        remove_ghaw_used_ports(args.ghaw_port_number)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()

