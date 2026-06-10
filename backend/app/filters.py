import re
from typing import Dict, List, Any, Optional

class DisplayFilterEvaluator:
    """
    Parses and evaluates Wireshark-style display filters on packet data dictionaries.
    Supported fields:
        - ip.src, ip.dst, ip.addr
        - ip.proto, proto
        - tcp.port, udp.port, tcp.srcport, tcp.dstport, udp.srcport, udp.dstport, port
        - tcp.flags.syn, tcp.flags.ack, tcp.flags.psh, tcp.flags.fin
        - frame.len, length
        - http, dns, arp, icmp, tcp, udp
    Supported comparisons: ==, !=, >, <, >=, <=, contains
    Supported logical operators: and, or, not, &&, ||, !
    """
    def __init__(self, filter_string: str):
        self.filter_string = filter_string.strip()
        self.tokens = self._tokenize(self.filter_string)
        self.postfix = self._to_postfix(self.tokens)

    def _tokenize(self, s: str) -> List[str]:
        pattern = r'\s*( && | \|\| | == | != | >= | <= | [><] | [!\(\)] | [a-zA-Z0-9_\-\.\:\*\/]+ )\s*'
        tokens = [t.strip() for t in re.split(pattern, s) if t and t.strip()]
        
        normalized = []
        for t in tokens:
            t_lower = t.lower()
            if t == '&&':
                normalized.append('and')
            elif t == '||':
                normalized.append('or')
            elif t == '!':
                normalized.append('not')
            elif t_lower in ('and', 'or', 'not'):
                normalized.append(t_lower)
            else:
                normalized.append(t)
        return normalized

    def _to_postfix(self, tokens: List[str]) -> List[str]:
        precedence = {'not': 3, 'and': 2, 'or': 1}
        output = []
        stack = []
        
        i = 0
        while i < len(tokens):
            token = tokens[i]
            if token in precedence:
                while stack and stack[-1] in precedence and precedence[stack[-1]] >= precedence[token]:
                    output.append(stack.pop())
                stack.append(token)
            elif token == '(':
                stack.append(token)
            elif token == ')':
                while stack and stack[-1] != '(':
                    output.append(stack.pop())
                if stack and stack[-1] == '(':
                    stack.pop()
            else:
                if i + 2 < len(tokens) and tokens[i+1] in ('==', '!=', '>', '<', '>=', '<=', 'contains'):
                    output.append(f"{tokens[i]} {tokens[i+1]} {tokens[i+2]}")
                    i += 2
                else:
                    output.append(token)
            i += 1
            
        while stack:
            output.append(stack.pop())
        return output

    def evaluate(self, pkt: Dict[str, Any]) -> bool:
        if not self.filter_string:
            return True
        if not self.postfix:
            return True
            
        stack: List[bool] = []
        
        for token in self.postfix:
            if token == 'not':
                if not stack:
                    return False
                val = stack.pop()
                stack.append(not val)
            elif token == 'and':
                if len(stack) < 2:
                    return False
                r = stack.pop()
                l = stack.pop()
                stack.append(l and r)
            elif token == 'or':
                if len(stack) < 2:
                    return False
                r = stack.pop()
                l = stack.pop()
                stack.append(l or r)
            else:
                stack.append(self._eval_term(token, pkt))
                
        return stack[0] if stack else True

    def _eval_term(self, term: str, pkt: Dict[str, Any]) -> bool:
        parts = term.split(' ')
        if len(parts) == 3:
            field, op, value = parts[0].lower(), parts[1], parts[2].strip('"\'')
            
            # Special compound address checks
            if field == 'ip.addr':
                src = str(pkt.get('src_ip', '')).lower()
                dst = str(pkt.get('dst_ip', '')).lower()
                val = value.lower()
                if op == '==':
                    return src == val or dst == val
                elif op == '!=':
                    return src != val and dst != val
                elif op == 'contains':
                    return val in src or val in dst
                return False

            # Special compound port checks
            if field in ('port', 'tcp.port', 'udp.port'):
                src_p = str(pkt.get('src_port') or '')
                dst_p = str(pkt.get('dst_port') or '')
                if op == '==':
                    return src_p == value or dst_p == value
                elif op == '!=':
                    return src_p != value and dst_p != value
                return False

            val = self._get_field_val(field, pkt)
            if val is None:
                return False
                
            if isinstance(val, int):
                try:
                    value = int(value)
                except ValueError:
                    return False
            elif isinstance(val, float):
                try:
                    value = float(value)
                except ValueError:
                    return False
            else:
                val = str(val).lower()
                value = str(value).lower()
                
            if op == '==':
                return val == value
            elif op == '!=':
                return val != value
            elif op == '>':
                return val > value
            elif op == '<':
                return val < value
            elif op == '>=':
                return val >= value
            elif op == '<=':
                return val <= value
            elif op == 'contains':
                return str(value) in str(val)
            return False
            
        else:
            field = term.lower()
            if field == 'tcp':
                return pkt.get('proto') == 'TCP'
            elif field == 'udp':
                return pkt.get('proto') == 'UDP'
            elif field == 'dns':
                return pkt.get('proto') == 'DNS'
            elif field == 'icmp':
                return pkt.get('proto') == 'ICMP'
            elif field == 'arp':
                return pkt.get('proto') == 'ARP'
            elif field == 'http':
                return (
                    pkt.get('dst_port') == 80 or 
                    pkt.get('src_port') == 80 or 
                    'http' in str(pkt.get('summary', '')).lower() or
                    'get ' in str(pkt.get('ascii_dump', '')).lower() or
                    'post ' in str(pkt.get('ascii_dump', '')).lower()
                )
            elif field == 'tcp.flags.syn':
                return 'S' in pkt.get('tcp_flags', '')
            elif field == 'tcp.flags.ack':
                return 'A' in pkt.get('tcp_flags', '')
            elif field == 'tcp.flags.fin':
                return 'F' in pkt.get('tcp_flags', '')
            elif field == 'tcp.flags.psh':
                return 'P' in pkt.get('tcp_flags', '')
            
            val = self._get_field_val(field, pkt)
            return val is not None and val != 'N/A'

    def _get_field_val(self, field: str, pkt: Dict[str, Any]) -> Any:
        field_map = {
            'ip.src': 'src_ip',
            'ip.dst': 'dst_ip',
            'tcp.srcport': 'src_port',
            'tcp.dstport': 'dst_port',
            'udp.srcport': 'src_port',
            'udp.dstport': 'dst_port',
            'frame.len': 'length',
            'length': 'length',
            'dns.query': 'dns_query',
            'proto': 'proto',
            'ip.proto': 'proto',
        }
        mapped = field_map.get(field)
        if mapped:
            return pkt.get(mapped)
        return pkt.get(field)
