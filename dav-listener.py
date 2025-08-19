import os
import sys
import argparse
import http.server
import socketserver
from typing import Optional, Union, List

class WebDAVServer:

    class WebDAVRequestHandler(http.server.SimpleHTTPRequestHandler):

        def __init__(self, *args, shares: Optional[dict] = None, **kwargs):
            self.shares = shares or {}
            super().__init__(*args, **kwargs)

        def translate_path(self, path):
            
            clean_path = path.split('?')[0].split('
            clean_path = clean_path.split('/')

            
            if len(clean_path) <= 1 or clean_path[1] == '':
                
                if self.shares:
                    first_share = list(self.shares.keys())[0]
                    share_path = self.shares[first_share]
                    return os.path.normpath(os.path.join(share_path, ''))

            
            share_name = clean_path[1]
            if share_name in self.shares:
                
                relative_path = os.path.join(*clean_path[2:])
                share_path = self.shares[share_name]
                full_path = os.path.normpath(os.path.join(share_path, relative_path))
                return full_path

            
            return super().translate_path(path)

        def do_PROPFIND(self):
            
            try:
                path = self.translate_path(self.path)

                
                if os.path.isdir(path):
                    content_type = 'inode/directory'
                    response_type = 'collection'
                else:
                    
                    content_type = self.guess_type(path)
                    response_type = ''

                
                stats = os.stat(path)

                
                xml_response = f"""<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
    <D:response>
        <D:href>{self.path}</D:href>
        <D:propstat>
            <D:prop>
                <D:creationdate>{self.date_time_string(stats.st_ctime)}</D:creationdate>
                <D:displayname>{os.path.basename(path)}</D:displayname>
                <D:getcontentlength>{stats.st_size}</D:getcontentlength>
                <D:getcontenttype>{content_type}</D:getcontenttype>
                <D:resourcetype>{response_type}</D:resourcetype>
                <D:getlastmodified>{self.date_time_string(stats.st_mtime)}</D:getlastmodified>
            </D:prop>
            <D:status>HTTP/1.1 200 OK</D:status>
        </D:propstat>
    </D:response>
</D:multistatus>"""

                
                self.send_response(207)
                self.send_header('Content-Type', 'application/xml; charset=utf-8')
                self.send_header('Content-Length', str(len(xml_response)))
                self.end_headers()
                self.wfile.write(xml_response.encode('utf-8'))

            except Exception as e:
                self.send_error(404, f"Error processing PROPFIND: {str(e)}")

        def end_headers(self):

            self.send_header('DAV', '1,2')
            self.send_header('Allow', 'GET,HEAD,POST,OPTIONS,PROPFIND,MKCOL,PUT,DELETE,COPY,MOVE')
            super().end_headers()

        def do_OPTIONS(self):

            self.send_response(200)
            self.send_header('DAV', '1,2')
            self.send_header('Allow', 'GET,HEAD,POST,OPTIONS,PROPFIND,MKCOL,PUT,DELETE,COPY,MOVE')
            self.send_header('Content-Length', '0')
            self.end_headers()

    def __init__(self,
                 shares: Optional[Union[dict, List[str]]] = None,
                 port: int = 8080,
                 interface: str = '0.0.0.0'):

        
        if shares is None:
            
            self.shares = {'files': os.getcwd()}
        elif isinstance(shares, list):
            
            self.shares = {f'share{i+1}': path for i, path in enumerate(shares)}
        elif isinstance(shares, dict):
            
            self.shares = shares
        else:
            raise ValueError("Shares must be a dictionary, list of paths, or None")

        
        for name, path in self.shares.items():
            if not os.path.isdir(path):
                raise ValueError(f"Share path for '{name}' is not a valid directory: {path}")

        self.port = port
        self.interface = interface
        self.server = None

    def start(self):
        
        handler = lambda *args, **kwargs: self.WebDAVRequestHandler(
            *args, shares=self.shares, **kwargs
        )

        
        with socketserver.TCPServer((self.interface, self.port), handler) as server:
            print(f"WebDAV Server Started:")
            print(f"  Interface: {self.interface}")
            print(f"  Port: {self.port}")
            print("  Shares:")
            for name, path in self.shares.items():
                print(f"    - /{name}: {path}")

            server.serve_forever()

    def start_threaded(self):
        import threading

        server_thread = threading.Thread(target=self.start, daemon=True)
        server_thread.start()
        return server_thread

def parse_shares(share_args):
    shares = {}
    for share_arg in share_args:
        if '=' in share_arg:
            
            name, path = share_arg.split('=', 1)
        else:
            
            path = share_arg
            name = 'share'

        
        path = os.path.abspath(os.path.expanduser(path))

        
        if not os.path.isdir(path):
            print(f"Error: {path} is not a valid directory", file=sys.stderr)
            sys.exit(1)

        shares[name] = path

    return shares

def create_parser():
    parser = argparse.ArgumentParser(
        description='Start an anonymous WebDAV server to share directories.',
        epilog='Examples:\n'
               '  %(prog)s /tmp                       
               '  %(prog)s /tmp documents=/home/user  
               '  %(prog)s -p 80 -i 0.0.0.0 /tmp      
    )
    parser.add_argument(
        'shares',
        nargs='*',
        default=[os.getcwd()],
        help='Directories to share. Optional format: [sharename=]path/to/directory. '
             'If no sharename is given, defaults to "share".'
    )
    parser.add_argument(
        '-p', '--port',
        type=int,
        default=8080,
        help='Port to listen on (default: 8080)'
    )
    parser.add_argument(
        '-i', '--interface',
        default='0.0.0.0',
        help='Network interface to bind to (default: 0.0.0.0)'
    )
    parser.add_argument(
        '-t', '--threaded',
        action='store_true',
        help='Run the server in a separate thread'
    )
    return parser

def create_webdav_server(
    shares: Optional[Union[dict, List[str]]] = None,
    port: int = 8080,
    interface: str = '0.0.0.0',
    threaded: bool = False
) -> WebDAVServer:
    server = WebDAVServer(
        shares=shares,
        port=port,
        interface=interface
    )

    if threaded:
        server.start_threaded()
    else:
        
        server.start()

    return server

def main():   
    parser = create_parser()
    args = parser.parse_args()

    shares = parse_shares(args.shares)

    server = create_webdav_server(
        shares=shares,
        port=args.port,
        interface=args.interface,
        threaded=args.threaded
    )

if __name__ == '__main__':
    main()