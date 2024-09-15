def create_filter_expression(src_ip=None, dst_ip=None, src_port=None, dst_port=None, protocol=None, custom_filter=None):
    filter_expr = custom_filter if custom_filter else ""
    
    if src_ip:
        filter_expr += f"src {src_ip} and "
    if dst_ip:
        filter_expr += f"dst {dst_ip} and "
    if src_port:
        filter_expr += f"src port {src_port} and "
    if dst_port:
        filter_expr += f"dst port {dst_port} and "
    if protocol:
        filter_expr += f"{protocol} and "
        
    return filter_expr.strip()  # Remove trailing " and "
