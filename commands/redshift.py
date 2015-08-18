# Copyright 2015 47Lining LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from nucleator.cli.utils import ValidateCustomerAction
from nucleator.cli.command import Command
from nucleator.cli import properties
from nucleator.cli import ansible
import os, subprocess, re
import string


class Redshift(Command):
    
    name = "redshift"
    
    node_types = [ "dw1.xlarge", "dw1.8xlarge", "ds1.xlarge", "ds1.8xlarge", "dw2.large", "dw2.8xlarge", "ds2.large", "ds2.8xlarge", "dc1.large", "dc1.8xlarge" ]

    cluster_types = ["single-node", "multi-node"]

    limits_map = {"dw1.xlarge" : (1, 32), "dw1.8xlarge" : (2, 128), "dw2.large" : (1, 32), "dw2.8xlarge" : (2, 128), "ds1.large": (1, 32), "ds1.8xlarge": (2, 128), "ds2.large": (1, 32), "ds2.8xlarge": (2, 128), "dc1.large": (2, 32), "dc1.8xlarge": (2, 100)}

    reserved_words = ['AES256', 'ALL', 'ALLOWOVERWRITE', 'ANALYSE', 'ANALYZE', 'AND', 'ANY', 'ARRAY', 'AS', 'ASC', 'AUTHORIZATION', 'BACKUP', 'BETWEEN', 'BINARY', 'BLANKSASNULL', 'BOTH', 'BYTEDICT', 'CASE', 'CAST', 'CHECK', 'COLLATE', 'COLUMN', 'CONSTRAINT', 'CREATE', 'CREDENTIALS', 'CROSS', 'CURRENT_DATE', 'CURRENT_TIME', 'CURRENT_TIMESTAMP', 'CURRENT_USER', 'CURRENT_USER_ID', 'DEFAULT', 'DEFERRABLE', 'DEFLATE', 'DEFRAG', 'DELTA', 'DELTA32K', 'DESC', 'DISABLE', 'DISTINCT', 'DO', 'ELSE', 'EMPTYASNULL', 'ENABLE', 'ENCODE', 'ENCRYPT', 'ENCRYPTION', 'END', 'EXCEPT', 'EXPLICIT', 'FALSE', 'FOR', 'FOREIGN', 'FREEZE', 'FROM', 'FULL', 'GLOBALDICT256', 'GLOBALDICT64K', 'GRANT', 'GROUP', 'GZIP', 'HAVING', 'IDENTITY', 'IGNORE', 'ILIKE', 'INITIALLY', 'INNER', 'INTERSECT', 'INTO', 'IS', 'ISNULL', 'JOIN', 'LEADING', 'LEFT', 'LIKE', 'LIMIT', 'LOCALTIME', 'LOCALTIMESTAMP', 'LUN', 'LUNS', 'LZO', 'LZOP', 'MINUS', 'MOSTLY13', 'MOSTLY32', 'MOSTLY8', 'NATURAL', 'NEW', 'NOT', 'NOTNULL', 'NULL', 'NULLS', 'OFF', 'OFFLINE', 'OFFSET', 'OLD', 'ON', 'ONLY', 'OPEN', 'OR', 'ORDER', 'OUTER', 'OVERLAPS', 'PARALLEL', 'PARTITION', 'PERCENT', 'PLACING', 'PRIMARY', 'RAW', 'READRATIO', 'RECOVER', 'REFERENCES', 'REJECTLOG', 'RESORT', 'RESTORE', 'RIGHT', 'SELECT', 'SESSION_USER', 'SIMILAR', 'SOME', 'SYSDATE', 'SYSTEM', 'TABLE', 'TAG', 'TDES', 'TEXT255', 'TEXT32K', 'THEN', 'TO', 'TOP', 'TRAILING', 'TRUE', 'TRUNCATECOLUMNS', 'UNION', 'UNIQUE', 'USER', 'USING', 'VERBOSE', 'WALLET', 'WHEN', 'WHERE', 'WITH', 'WITHOUT']

    def parser_init(self, subparsers):
        """
        Initialize parsers for this command.
        """
        # add parser for builder command
        redshift_parser = subparsers.add_parser('redshift')
        redshift_subparsers=redshift_parser.add_subparsers(dest="subcommand")

        # provision subcommand
        redshift_provision=redshift_subparsers.add_parser('provision', help="Provision a new nucleator redshift stackset")
        redshift_provision.add_argument("--customer", required=True, action=ValidateCustomerAction, help="Name of customer from nucleator config")
        redshift_provision.add_argument("--cage", required=True, help="Name of cage from nucleator config")
        redshift_provision.add_argument("--cluster_name", required=True, help="Name of the redshift cluster to provision")
        redshift_provision.add_argument("--cluster_type", required=False, help="Type of cluster to provision ('single-node' or 'multi-node') defaults to 'single-node'")
        redshift_provision.add_argument("--num_nodes", required=False, help="Number of nodes to provision (default: 1)")
        redshift_provision.add_argument("--node_type", required=False, help="Type of nodes to provision (default: 'dw2.large')")
        redshift_provision.add_argument("--username", required=True, help="Master username for the provisioned redshift cluster")
        redshift_provision.add_argument("--password", required=True, help="Master password for the provisioned redshift cluster")
        redshift_provision.add_argument("--database_name", required=False, help="Name of initial database to provision")
        redshift_provision.add_argument("--encrypted", required=False, help="Whether to encrypt data at rest (default: 'false')")
        redshift_provision.add_argument("--public", required=False, help="Whether the cluster can be accessed from a public network (default: 'false')")
        redshift_provision.add_argument("--port", required=False, help="The port number for the database (default: 5439)")

        # delete subcommand
        redshift_delete=redshift_subparsers.add_parser('delete', help="delete specified nucleator redshift stackset")
        redshift_delete.add_argument("--customer", action=ValidateCustomerAction, required=True, help="Name of customer from nucleator config")
        redshift_delete.add_argument("--cage", required=True, help="Name of cage from nucleator config")
        redshift_delete.add_argument("--cluster_name", required=True, help="Name of redshift cluster")

    def provision(self, **kwargs):
        """
        This command provisions a new Redshift cluster in the indicated Customer Cage. 
        """
        cli = Command.get_cli(kwargs)
        cage = kwargs.get("cage", None)
        customer = kwargs.get("customer", None)
        if cage is None or customer is None:
            raise ValueError("cage and customer must be specified")
        extra_vars={
            "cage_name": cage,
            "customer_name": customer,
            "verbosity": kwargs.get("verbosity", None),
        }

        extra_vars["redshift_deleting"]=kwargs.get("redshift_deleting", False)

        cluster_name = kwargs.get("cluster_name", None)
        if cluster_name is None:
            raise ValueError("cluster_name must be specified")
        self.validate_cluster_name(cluster_name)
        extra_vars["cluster_name"] = cluster_name
        
        extra_vars["cli_stackset_name"] = "redshift"
        extra_vars["cli_stackset_instance_name"] = cluster_name

        cluster_type = kwargs.get("cluster_type", None)
        if cluster_type is None:
            cluster_type = "single-node"
        if not cluster_type in self.cluster_types:
            raise ValueError("unsupported redshift cluster type")
        extra_vars["cluster_type"] = cluster_type

        node_type = kwargs.get("node_type", None)
        if node_type is None:
            node_type = "dw2.large"
        if not node_type in self.node_types:
            raise ValueError("invalid value for node_type")
        extra_vars["node_type"] = node_type
        
        node_limits = self.limits_map.get(node_type)
        default_num_nodes = node_limits[0]
        num_nodes = kwargs.get("num_nodes", None)
        if num_nodes is None:
            num_nodes = default_num_nodes
        try:
            num_nodes = int(num_nodes)
        except ValueError:
            raise ValueError("invalid value for num_nodes")
        if num_nodes < node_limits[0] or num_nodes > node_limits[1]:
            raise ValueError("value given for num_nodes exceeds limits for selected node_type (%s)" % node_type)
        extra_vars["num_nodes"] = num_nodes

        database_name = kwargs.get("database_name", None)
        if database_name is None:
            database_name = "defaultdb"
        self.validate_database_name(database_name)
        extra_vars["database_name"] = database_name
        
        master_username = kwargs.get("username", None)
        if master_username is None:
            raise ValueError("username must be provided")
        self.validate_master_username(master_username)
        extra_vars["master_username"] = master_username

        master_password = kwargs.get("password", None)
        if master_password is None:
            raise ValueError("password must be provided")
        self.validate_master_password(master_password)
        extra_vars["master_password"] = master_password

        is_encrypted = kwargs.get("encrypted", None)
        if is_encrypted is None:
            is_encrypted = "false"
        is_encrypted = self.booleanize(is_encrypted)
        extra_vars["is_encrypted"] = is_encrypted
        
        is_public = kwargs.get("public", None)
        if is_public is None:
            is_public = "false"
        is_public = self.booleanize(is_public)
        extra_vars["is_public"] = is_public

        port_number = kwargs.get("port", None)
        if port_number is None:
            port_number = "5439"
        extra_vars["port_number"] = port_number
        
        command_list = []
        command_list.append("account")
        command_list.append("cage")
        command_list.append("redshift")

        cli.obtain_credentials(commands = command_list, cage=cage, customer=customer, verbosity=kwargs.get("verbosity", None))
        
        return cli.safe_playbook(self.get_command_playbook("redshift_provision.yml"),
                                 is_static=True, # dynamic inventory not required
                                 **extra_vars
        )

    def validate_cluster_name(self, value):
        alphanum = re.compile("^[a-z0-9]*$")
        if alphanum.match(value) is None:
            raise ValueError("Invalid cluster name - only lowercase alphanumeric characters are allowed")
        if len(value) < 1 or len(value) > 63:
            raise ValueError("Invalid cluster name - must be from 1 to 63 characters")
        if not value[0] in string.ascii_lowercase:
            raise ValueError("Invalid cluster name - must begin with a lowercase letter")
        if value.find("--") > -1:
            raise ValueError("Invalid cluster name - cannot contain consecutive dashes")
        if value[-1] == '-':
            raise ValueError("Invalid cluster name - cannot end with a dash")

    def validate_database_name(self, value):
        alphanum = re.compile("^[a-z0-9]*$")
        if alphanum.match(value) is None:
            raise ValueError("Invalid database name - only lowercase alphanumeric characters are allowed")
        if len(value) < 1 or len(value) > 64:
            raise ValueError("Invalid database name - must be from 1 to 64 characters")
        if value in self.reserved_words:
            raise ValueError("Invalid database name - cannot be reserved word (%s)" % word.lower())
 
    def validate_master_username(self, value):
        alphanum = re.compile("^[a-z0-9-]*$")
        if alphanum.match(value) is None:
            raise ValueError("Invalid username - only lowercase alphanumeric characters are allowed")
        if len(value) < 1 or len(value) > 128:
            raise ValueError("Invalid username - must be from 1 to 128 characters")
        if not value[0] in string.ascii_lowercase:
            raise ValueError("Invalid username - must begin with a lowercase letter")
        if value in self.reserved_words:
            raise ValueError("Invalid username - cannot be reserved word (%s)" % word.lower())

    def validate_master_password(self, value):
        if len(value) < 8 or len(value) > 64:
            raise ValueError("Invalid password - must be from 8 to 64 characters")
        if not re.search('\d+', value):
            raise ValueError("Invalid password - must contain at least 1 number")
        if not re.search('[a-z]', value):
            raise ValueError("Invalid password - must contain at least 1 lowercase letter")
        if not re.search('[A-Z]', value):
            raise ValueError("Invalid password - must contain at least 1 uppercase letter")
    
    def booleanize(self, value):
        result = value.lower()
        if not result in ("true", "false"):
            raise ValueError("Invalid boolean value: %s" % value)
        return result

    def delete(self, **kwargs):
        """
        This command deletes a previously provisioned Redshift from the indicated Customer Cage.
        """

        kwargs["redshift_deleting"]=True
        kwargs["username"] = "master"
        kwargs["password"] = "Pa55word"

        return self.provision(**kwargs)


# Create the singleton for auto-discovery
command = Redshift()
