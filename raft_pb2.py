# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# NO CHECKED-IN PROTOBUF GENCODE
# source: raft.proto
# Protobuf Python Version: 5.29.0
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import runtime_version as _runtime_version
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
_runtime_version.ValidateProtobufRuntimeVersion(
    _runtime_version.Domain.PUBLIC,
    5,
    29,
    0,
    '',
    'raft.proto'
)
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\nraft.proto\x12\x04raft\"g\n\x12RequestVoteRequest\x12\x0c\n\x04term\x18\x01 \x01(\x05\x12\x14\n\x0c\x63\x61ndidate_id\x18\x02 \x01(\t\x12\x16\n\x0elast_log_index\x18\x03 \x01(\x05\x12\x15\n\rlast_log_term\x18\x04 \x01(\x05\"9\n\x13RequestVoteResponse\x12\x0c\n\x04term\x18\x01 \x01(\x05\x12\x14\n\x0cvote_granted\x18\x02 \x01(\x08\"\x8e\x01\n\x14\x41ppendEntriesRequest\x12\x0c\n\x04term\x18\x01 \x01(\x05\x12\x11\n\tleader_id\x18\x02 \x01(\t\x12\x16\n\x0eprev_log_index\x18\x03 \x01(\x05\x12\x15\n\rprev_log_term\x18\x04 \x01(\x05\x12\x0f\n\x07\x65ntries\x18\x05 \x03(\t\x12\x15\n\rleader_commit\x18\x06 \x01(\x05\"6\n\x15\x41ppendEntriesResponse\x12\x0c\n\x04term\x18\x01 \x01(\x05\x12\x0f\n\x07success\x18\x02 \x01(\x08\"P\n\x0e\x41\x64\x64NodeRequest\x12\x0f\n\x07node_id\x18\x01 \x01(\t\x12\x0c\n\x04host\x18\x02 \x01(\t\x12\x0c\n\x04port\x18\x03 \x01(\x05\x12\x11\n\traft_port\x18\x04 \x01(\x05\"3\n\x0f\x41\x64\x64NodeResponse\x12\x0f\n\x07success\x18\x01 \x01(\x08\x12\x0f\n\x07message\x18\x02 \x01(\t\"J\n\x08NodeInfo\x12\x0f\n\x07node_id\x18\x01 \x01(\t\x12\x0c\n\x04host\x18\x02 \x01(\t\x12\x0c\n\x04port\x18\x03 \x01(\x05\x12\x11\n\traft_port\x18\x04 \x01(\x05\"4\n\x13\x43lusterConfigUpdate\x12\x1d\n\x05nodes\x18\x01 \x03(\x0b\x32\x0e.raft.NodeInfo\"?\n\x1bUpdateClusterConfigResponse\x12\x0f\n\x07success\x18\x01 \x01(\x08\x12\x0f\n\x07message\x18\x02 \x01(\t2\xa8\x02\n\x0bRaftService\x12\x42\n\x0bRequestVote\x12\x18.raft.RequestVoteRequest\x1a\x19.raft.RequestVoteResponse\x12H\n\rAppendEntries\x12\x1a.raft.AppendEntriesRequest\x1a\x1b.raft.AppendEntriesResponse\x12\x36\n\x07\x41\x64\x64Node\x12\x14.raft.AddNodeRequest\x1a\x15.raft.AddNodeResponse\x12S\n\x13UpdateClusterConfig\x12\x19.raft.ClusterConfigUpdate\x1a!.raft.UpdateClusterConfigResponseb\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'raft_pb2', _globals)
if not _descriptor._USE_C_DESCRIPTORS:
  DESCRIPTOR._loaded_options = None
  _globals['_REQUESTVOTEREQUEST']._serialized_start=20
  _globals['_REQUESTVOTEREQUEST']._serialized_end=123
  _globals['_REQUESTVOTERESPONSE']._serialized_start=125
  _globals['_REQUESTVOTERESPONSE']._serialized_end=182
  _globals['_APPENDENTRIESREQUEST']._serialized_start=185
  _globals['_APPENDENTRIESREQUEST']._serialized_end=327
  _globals['_APPENDENTRIESRESPONSE']._serialized_start=329
  _globals['_APPENDENTRIESRESPONSE']._serialized_end=383
  _globals['_ADDNODEREQUEST']._serialized_start=385
  _globals['_ADDNODEREQUEST']._serialized_end=465
  _globals['_ADDNODERESPONSE']._serialized_start=467
  _globals['_ADDNODERESPONSE']._serialized_end=518
  _globals['_NODEINFO']._serialized_start=520
  _globals['_NODEINFO']._serialized_end=594
  _globals['_CLUSTERCONFIGUPDATE']._serialized_start=596
  _globals['_CLUSTERCONFIGUPDATE']._serialized_end=648
  _globals['_UPDATECLUSTERCONFIGRESPONSE']._serialized_start=650
  _globals['_UPDATECLUSTERCONFIGRESPONSE']._serialized_end=713
  _globals['_RAFTSERVICE']._serialized_start=716
  _globals['_RAFTSERVICE']._serialized_end=1012
# @@protoc_insertion_point(module_scope)
