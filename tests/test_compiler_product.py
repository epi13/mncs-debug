"""Direct compiler product/source-map join over the existing live VM model."""
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from mncs_debug.targets import load_compiler_product, TargetError
from mncs_debug.live import start_session, step_session, continue_session, inspect_session, close_session

ROOT=Path(__file__).resolve().parents[1];WORKSPACE=ROOT.parent
COMPILER=WORKSPACE/'mncs-compiler';VM=WORKSPACE/'mncs-vm/target/debug/mncs-vm'

@unittest.skipUnless(VM.is_file() and (COMPILER/'.bootstrap/target/release/mncs-compiler-stage0-probe').is_file(),'selected compiler/VM not built')
class CompilerProductTests(unittest.TestCase):
    def test_direct_source_map_stop_step_and_terminal_evidence(self):
        spec=importlib.util.spec_from_file_location('debug_test_compiler',COMPILER/'tools/vm_provider.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw);product=module.CompilerProvider(COMPILER).emit({'schema_version':'mncs.compiler-vm-request/1','source':str(WORKSPACE/'mncs-vm/tests/corpus/arith.mncs'),'logical_name':'arith.mncs'},root/'cache')
            correspondence=load_compiler_product(Path(product['product']))
            operations=[r for r in correspondence['source_map']['operations'] if r['correspondence'].startswith('selected-ssa') and '::add3' in r['function_identity']]
            self.assertTrue(operations)
            session_root=root/'live'
            try:
                started=start_session(root=session_root,vm_path=VM,artifact_path=correspondence['artifact_path'],target={'module':'mncs.vmcorpus.arith.v1','name':'add3'},arguments=[{'integer':{'value':10,'type':{'bits':64,'signed':True}}}],capture='bounded',stops=[{'id':'source-stop','target':{'kind':'operation','instruction':operations[0]['identity']}}])
                self.assertEqual(started['session']['artifact'],correspondence['artifact_identity'])
                self.assertEqual(started['event']['event'],'stopped')
                point=started['event']['stop']['safe_point'];self.assertEqual(point['instruction'],operations[0]['identity'])
                self.assertEqual(operations[0]['source_span']['line'],32)
                inspection=inspect_session(session_root);self.assertTrue(inspection)
                stepped=step_session(session_root,'in',120);self.assertEqual(stepped['event']['event'],'stopped')
                finished=continue_session(session_root,120);self.assertEqual(finished['event']['event'],'finished')
                self.assertEqual(finished['event']['record']['artifact_id'],correspondence['artifact_identity'])
                self.assertGreater(finished['event']['record']['usage']['steps'],0)
            finally:close_session(session_root)
            path=Path(product['product']);changed=json.loads(path.read_text());changed['artifact']['identity']='forged';path.write_text(json.dumps(changed))
            with self.assertRaises(TargetError):load_compiler_product(path)
