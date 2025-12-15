# Copyright (c) 2025 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""
Task Router Action Plugin

This plugin determines which task files should be executed based on:
- fabric_type: The type of fabric (VXLAN_EVPN, eBGP_VXLAN, ISN, MSD, MCFG, External)
- change_flags: Dictionary of boolean flags indicating what has changed
- role: The role being executed (create, deploy, remove)

Usage in Ansible:
    - name: Determine tasks to run
      cisco.nac_dc_vxlan.dtc.task_router:
        fabric_type: "{{ data_model_extended.vxlan.fabric.type }}"
        change_flags: "{{ change_flags }}"
        role: "create"
      register: router_result

    - name: Execute routed tasks
      ansible.builtin.include_tasks: "{{ task_file }}"
      loop: "{{ router_result.task_files }}"
      loop_control:
        loop_var: task_file
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible.plugins.action import ActionBase
from ansible.utils.display import Display

display = Display()


# Mapping of fabric types to their sub_main files
FABRIC_TYPE_MAPPING = {
    'VXLAN_EVPN': 'sub_main_vxlan.yml',
    'eBGP_VXLAN': 'sub_main_ebgp_vxlan.yml',
    'ISN': 'sub_main_isn.yml',
    'MSD': 'sub_main_msd.yml',
    'MCFG': 'sub_main_mcfg.yml',
    'External': 'sub_main_external.yml',
}


class ActionModule(ActionBase):
    """
    Task Router Action Plugin
    
    Routes task execution based on fabric type and change flags.
    Returns a list of task files that should be executed.
    """

    def run(self, tmp=None, task_vars=None):
        results = super(ActionModule, self).run(tmp, task_vars)
        results['failed'] = False
        results['changed'] = False
        
        # Get parameters
        fabric_type = self._task.args.get('fabric_type')
        change_flags = self._task.args.get('change_flags', {})
        role = self._task.args.get('role', 'create')
        
        # Additional context for MSD fabric type
        child_fabrics_changed = self._task.args.get('child_fabrics_vrfs_networks_changed', [])
        
        # Validate required parameters
        if not fabric_type:
            results['failed'] = True
            results['msg'] = "Missing required parameter 'fabric_type'"
            return results
        
        if fabric_type not in FABRIC_TYPE_MAPPING:
            results['failed'] = True
            results['msg'] = f"Unknown fabric_type: {fabric_type}. Valid types: {list(FABRIC_TYPE_MAPPING.keys())}"
            return results
        
        # Determine if any changes were detected
        changes_detected_any = change_flags.get('changes_detected_any', False)
        
        # Initialize result
        task_files = []
        skipped_reason = None
        
        # Route based on fabric type and role
        if role == 'create':
            task_files, skipped_reason = self._route_create_tasks(
                fabric_type, change_flags, changes_detected_any
            )
        elif role == 'deploy':
            task_files, skipped_reason = self._route_deploy_tasks(
                fabric_type, change_flags, changes_detected_any, child_fabrics_changed
            )
        elif role == 'remove':
            task_files, skipped_reason = self._route_remove_tasks(
                fabric_type, change_flags, changes_detected_any
            )
        else:
            results['failed'] = True
            results['msg'] = f"Unknown role: {role}. Valid roles: create, deploy, remove"
            return results
        
        # Set results
        results['task_files'] = task_files
        results['fabric_type'] = fabric_type
        results['role'] = role
        results['changes_detected_any'] = changes_detected_any
        results['skipped'] = len(task_files) == 0
        results['skipped_reason'] = skipped_reason
        
        # Log the routing decision
        if task_files:
            display.v(f"TaskRouter: Routing {fabric_type}/{role} to {len(task_files)} task file(s)")
            for tf in task_files:
                display.vv(f"  - {tf}")
        else:
            display.v(f"TaskRouter: Skipping {fabric_type}/{role} - {skipped_reason}")
        
        return results
    
    def _route_create_tasks(self, fabric_type, change_flags, changes_detected_any):
        """Route tasks for the create role."""
        
        if not changes_detected_any:
            return [], "No changes detected"
        
        # For create role, we include the sub_main file for the fabric type
        return [FABRIC_TYPE_MAPPING[fabric_type]], None
    
    def _route_deploy_tasks(self, fabric_type, change_flags, changes_detected_any, child_fabrics_changed):
        """Route tasks for the deploy role."""
        
        # MSD and MCFG have special conditions
        if fabric_type == 'MSD':
            if changes_detected_any or len(child_fabrics_changed) > 0:
                return [FABRIC_TYPE_MAPPING[fabric_type]], None
            return [], "No changes detected and no child fabric changes"
        
        if fabric_type == 'MCFG':
            if changes_detected_any:
                return [FABRIC_TYPE_MAPPING[fabric_type]], None
            return [], "No changes detected"
        
        # Standard fabric types
        if not changes_detected_any:
            return [], "No changes detected"
        
        return [FABRIC_TYPE_MAPPING[fabric_type]], None
    
    def _route_remove_tasks(self, fabric_type, change_flags, changes_detected_any):
        """Route tasks for the remove role."""
        
        # MSD and MCFG always run (they check changes internally)
        if fabric_type in ['MSD', 'MCFG']:
            return [FABRIC_TYPE_MAPPING[fabric_type]], None
        
        # Standard fabric types need changes_detected_any
        if not changes_detected_any:
            return [], "No changes detected"
        
        return [FABRIC_TYPE_MAPPING[fabric_type]], None
