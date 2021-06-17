from pyvelociraptor import api_pb2
from pyvelociraptor import api_pb2_grpc

import yaml
import grpc
import json
import os 


class Velociraptor:
    '''
    This script connects to the Velociraptor API through gRPC and takes VQL queries as variables.
    '''
    def __init__(self):
        '''
        Sets all the necessary configurations.
        '''
        super().__init__()
        config_path = os.path.dirname(os.path.abspath(__file__))
        filename = os.path.join(config_path, 'api_client.yaml')

        self.config = yaml.safe_load(open(filename).read())
        self.creds = grpc.ssl_channel_credentials(
                root_certificates=self.config["ca_certificate"].encode("utf8"),
                private_key=self.config["client_private_key"].encode("utf8"),
                certificate_chain=self.config["client_cert"].encode("utf8"))

        self.options = (('grpc.ssl_target_name_override', "VelociraptorServer",),)


    def query(self, query, destination):
        '''
        Connects and calls the Velociraptor API and performs the defined query.
        :param query: The VQL query
        :type query: str
        :param destination: The destination folder
        :type destination: str 
        '''
        with grpc.secure_channel(self.config["api_connection_string"], self.creds, self.options) as channel:
                stub = api_pb2_grpc.APIStub(channel)
                
                request = api_pb2.VQLCollectorArgs(Query=[api_pb2.VQLRequest(VQL=query,)])
                
                for response in stub.Query(request):
                    if response.Response:
                        for row in json.loads(response.Response):
                            with open(destination, 'a', encoding='utf-8') as f:
                                json.dump(row, f, ensure_ascii=False, indent=4)
