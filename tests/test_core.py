from backend.models import Flow
def test_v4_model():
 f=Flow(flow_id='pcap-1',src_ip='10.0.0.1',dst_ip='10.0.0.2',protocol='TCP'); assert f.flow_id=='pcap-1'
