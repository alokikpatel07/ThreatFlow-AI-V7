from typing import Literal, Optional
from pydantic import BaseModel, Field
Scenario=Literal['benign','mixed','syn_flood','beacon','dga','dns_tunnel','tls_anomaly','scan','data_exfiltration']
class Flow(BaseModel):
    timestamp: Optional[float]=None; flow_id:str; src_ip:str; dst_ip:str; src_port:int=0; dst_port:int=0; protocol:str; packets:int=1; out_bytes:int=0; in_bytes:int=0; duration_ms:float=0.0; tcp_flags:str=''; dns_name:Optional[str]=None; dns_record_type:Optional[str]=None; tls_fingerprint:Optional[str]=None; tls_ja3:Optional[str]=None; tls_ja3s:Optional[str]=None; tls_ja4:Optional[str]=None; quic_version:Optional[str]=None; quic_sni:Optional[str]=None
    @property
    def bytes_out(self): return self.out_bytes
    @property
    def bytes_in(self): return self.in_bytes
    @property
    def dns_query(self): return self.dns_name
class StartSimulation(BaseModel):
    scenario:Scenario='mixed'; rate:int=Field(default=20,ge=1,le=500); seconds:int=Field(default=0,ge=0,le=3600)
class IngestResponse(BaseModel): alert:Optional[dict]=None; flow_id:str
