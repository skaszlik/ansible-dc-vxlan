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
Batch File Processor Action Plugin

This plugin processes multiple file operations in parallel to reduce playbook execution time.
It replaces the repetitive 7-step pattern (set_fact, stat, backup, delete, template, read, diff)
that is duplicated across many ndfc_*.yml task files.

Usage:
    - name: Process Interface Files in Parallel
      cisco.nac_dc_vxlan.common.batch_file_processor:
        path_name: "{{ role_path }}/files/vxlan/{{ fabric_name }}/"
        template_path: "{{ role_path }}/templates"
        fabric_type: "{{ data_model_extended.vxlan.fabric.type }}"
        fabric_name: "{{ data_model_extended.vxlan.fabric.name }}"
        role_path: "{{ common_role_path }}"
        check_roles: "{{ check_roles }}"
        data_model_extended: "{{ data_model_extended }}"
        max_workers: 8
        files:
          - file_name: ndfc_interface_routed.yml
            template: ndfc_interfaces/ndfc_interface_routed.j2
            result_var: interface_routed
            change_flag: changes_detected_interface_routed
            condition: "data_model_extended.vxlan.topology.interfaces.modes.routed.count > 0"
          - file_name: ndfc_interface_trunk.yml
            template: ndfc_interfaces/ndfc_interface_trunk.j2
            result_var: interface_trunk
            change_flag: changes_detected_interface_trunk
            condition: "data_model_extended.vxlan.topology.interfaces.modes.trunk.count > 0"
      register: batch_result
      delegate_to: localhost

    # Results are available as:
    # batch_result.results.interface_routed - the parsed YAML data
    # batch_result.change_flags.changes_detected_interface_routed - boolean
    # batch_result.diff_results.interface_routed - diff details
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import hashlib
import json
import os
import re
import shutil
import yaml
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

from ansible.plugins.action import ActionBase
from ansible.template import Templar
from ansible.utils.display import Display

display = Display()


class FileProcessor:
    """Handles file operations for a single file configuration."""

    # Pattern to normalize omit placeholders in file comparisons
    OMIT_PATTERN = re.compile(r'__omit_place_holder__\S+')

    def __init__(
        self,
        file_config: Dict[str, Any],
        path_name: str,
        template_path: str,
        templar: Templar,
        task_vars: Dict[str, Any],
        fabric_type: str,
        fabric_name: str,
        role_path: str,
        check_roles: Dict[str, Any],
    ):
        self.file_config = file_config
        self.path_name = path_name
        self.template_path = template_path
        self.templar = templar
        self.task_vars = task_vars
        self.fabric_type = fabric_type
        self.fabric_name = fabric_name
        self.role_path = role_path
        self.check_roles = check_roles

        # Extract file configuration
        self.file_name = file_config['file_name']
        self.template = file_config['template']
        self.result_var = file_config['result_var']
        self.change_flag = file_config['change_flag']
        self.condition = file_config.get('condition')
        self.use_diff_compare = file_config.get('use_diff_compare', False)

        # Paths
        self.file_path = os.path.join(path_name, self.file_name)
        self.file_path_old = f"{self.file_path}.old"
        self.template_file = os.path.join(template_path, self.template)

    def process(self) -> Dict[str, Any]:
        """
        Process a single file through the complete workflow:
        1. Stat previous file
        2. Backup previous file if exists
        3. Delete previous file
        4. Render template to new file
        5. Read and parse the result
        6. Diff previous and current files
        7. Determine change flag value

        Returns:
            Dict containing:
                - result_var: name of the variable
                - result_data: parsed YAML data
                - change_flag: name of the change flag
                - file_changed: boolean indicating if file changed
                - diff_result: detailed diff information (if use_diff_compare)
                - error: error message if any
        """
        result = {
            'result_var': self.result_var,
            'result_data': [],
            'change_flag': self.change_flag,
            'file_changed': False,
            'diff_result': None,
            'error': None,
        }

        try:
            # Step 1: Stat previous file
            previous_exists = os.path.exists(self.file_path)

            # Step 2: Backup previous file if exists
            if previous_exists:
                shutil.copy2(self.file_path, self.file_path_old)

            # Step 3: Delete previous file (will be replaced by template)
            if previous_exists:
                os.remove(self.file_path)

            # Step 4: Render template to new file
            self._render_template()

            # Step 5: Read and parse result (conditionally)
            if self._should_read_result():
                result['result_data'] = self._read_yaml_file(self.file_path)

            # Step 6 & 7: Diff and determine change flag
            file_changed = self._check_file_changed()
            result['file_changed'] = file_changed

            # Handle diff_compare if needed
            if self.use_diff_compare and os.path.exists(self.file_path_old):
                result['diff_result'] = self._compute_diff_compare()

            # Cleanup old file if no changes
            if not file_changed and os.path.exists(self.file_path_old):
                os.remove(self.file_path_old)

        except Exception as e:
            result['error'] = str(e)
            display.warning(f"Error processing {self.file_name}: {e}")

        return result

    def _render_template(self) -> None:
        """Render Jinja2 template to the output file."""
        # Ensure output directory exists
        os.makedirs(os.path.dirname(self.file_path), exist_ok=True)

        # Read template file
        with open(self.template_file, 'r') as f:
            template_content = f.read()

        # Render template using Ansible's Templar
        rendered = self.templar.template(template_content)

        # Write rendered content to output file
        with open(self.file_path, 'w') as f:
            f.write(rendered)

        # Set file permissions (0644)
        os.chmod(self.file_path, 0o644)

    def _should_read_result(self) -> bool:
        """Check if the condition for reading the result is met."""
        if not self.condition:
            return True

        try:
            # Evaluate the condition using Templar
            condition_template = "{{ " + self.condition + " }}"
            result = self.templar.template(condition_template)
            return bool(result)
        except Exception as e:
            display.vvv(f"Condition evaluation failed for {self.file_name}: {e}")
            return False

    def _read_yaml_file(self, file_path: str) -> Any:
        """Read and parse a YAML file."""
        with open(file_path, 'r') as f:
            content = f.read()

        if not content.strip():
            return []

        return yaml.safe_load(content) or []

    def _check_file_changed(self) -> bool:
        """
        Compare previous and current files using MD5 hash.
        Handles omit placeholder normalization.
        """
        # If no previous file, content has changed
        if not os.path.exists(self.file_path_old):
            return True

        # Read both files
        with open(self.file_path_old, 'r') as f:
            data_previous = f.read()

        with open(self.file_path, 'r') as f:
            data_current = f.read()

        # Compare MD5 hashes
        md5_previous = hashlib.md5(data_previous.encode()).hexdigest()
        md5_current = hashlib.md5(data_current.encode()).hexdigest()

        if md5_previous == md5_current:
            return False

        # Normalize omit placeholders and try again
        data_previous_normalized = self.OMIT_PATTERN.sub('NORMALIZED', data_previous)
        data_current_normalized = self.OMIT_PATTERN.sub('NORMALIZED', data_current)

        md5_previous = hashlib.md5(data_previous_normalized.encode()).hexdigest()
        md5_current = hashlib.md5(data_current_normalized.encode()).hexdigest()

        return md5_previous != md5_current

    def _compute_diff_compare(self) -> Dict[str, Any]:
        """
        Compute detailed diff between old and new files.
        Returns updated, removed, and equal items.
        """
        if not os.path.exists(self.file_path_old):
            return {'updated': [], 'removed': [], 'equal': []}

        old_data = self._read_yaml_file(self.file_path_old)
        new_data = self._read_yaml_file(self.file_path)

        # Simple comparison - can be enhanced based on dtc.diff_compare logic
        if old_data == new_data:
            return {'updated': [], 'removed': [], 'equal': old_data if isinstance(old_data, list) else [old_data]}

        # For now, return basic diff info
        return {
            'updated': new_data if isinstance(new_data, list) else [new_data],
            'removed': [],
            'equal': [],
            'changed': True
        }


class ActionModule(ActionBase):
    """
    Ansible action plugin for batch file processing.

    This plugin processes multiple file operations in parallel using ThreadPoolExecutor,
    significantly reducing execution time compared to sequential Ansible tasks.
    """

    REQUIRED_ARGS = ['path_name', 'template_path', 'fabric_type', 'fabric_name', 'role_path', 'files']

    def run(self, tmp=None, task_vars=None):
        """Execute the batch file processing."""
        result = super(ActionModule, self).run(tmp, task_vars)
        task_vars = task_vars or {}

        # Validate required arguments
        validation_error = self._validate_args()
        if validation_error:
            result['failed'] = True
            result['msg'] = validation_error
            return result

        # Extract arguments
        path_name = self._task.args['path_name']
        template_path = self._task.args['template_path']
        fabric_type = self._task.args['fabric_type']
        fabric_name = self._task.args['fabric_name']
        role_path = self._task.args['role_path']
        files = self._task.args['files']
        check_roles = self._task.args.get('check_roles', {'save_previous': True})
        max_workers = self._task.args.get('max_workers', min(8, len(files)))

        # Initialize Templar for template rendering
        templar = Templar(loader=self._loader, variables=task_vars)

        # Ensure output directory exists
        os.makedirs(path_name, exist_ok=True)

        # Process files in parallel
        results = {}
        change_flags = {}
        diff_results = {}
        errors = []

        display.vvv(f"Processing {len(files)} files with {max_workers} workers")

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all file processing tasks
            future_to_file = {}
            for file_config in files:
                processor = FileProcessor(
                    file_config=file_config,
                    path_name=path_name,
                    template_path=template_path,
                    templar=templar,
                    task_vars=task_vars,
                    fabric_type=fabric_type,
                    fabric_name=fabric_name,
                    role_path=role_path,
                    check_roles=check_roles,
                )
                future = executor.submit(processor.process)
                future_to_file[future] = file_config['file_name']

            # Collect results as they complete
            for future in as_completed(future_to_file):
                file_name = future_to_file[future]
                try:
                    file_result = future.result()
                    result_var = file_result['result_var']

                    results[result_var] = file_result['result_data']
                    change_flags[file_result['change_flag']] = file_result['file_changed']

                    if file_result['diff_result']:
                        diff_results[result_var] = file_result['diff_result']

                    if file_result['error']:
                        errors.append(f"{file_name}: {file_result['error']}")

                except Exception as e:
                    errors.append(f"{file_name}: {str(e)}")

        # Update change flags in the JSON file if any files changed
        if check_roles.get('save_previous', True):
            self._update_change_flags(change_flags, fabric_type, fabric_name, role_path)

        # Build final result
        result['changed'] = any(change_flags.values())
        result['results'] = results
        result['change_flags'] = change_flags
        result['diff_results'] = diff_results
        result['files_processed'] = len(files)

        if errors:
            result['warnings'] = errors

        display.vvv(f"Batch processing complete: {len(files)} files, {sum(1 for v in change_flags.values() if v)} changed")

        return result

    def _validate_args(self) -> Optional[str]:
        """Validate required arguments are present."""
        for arg in self.REQUIRED_ARGS:
            if arg not in self._task.args:
                return f"Missing required argument: {arg}"

        files = self._task.args.get('files', [])
        if not files:
            return "No files specified for processing"

        # Validate each file config
        required_file_keys = ['file_name', 'template', 'result_var', 'change_flag']
        for i, file_config in enumerate(files):
            for key in required_file_keys:
                if key not in file_config:
                    return f"File config {i} missing required key: {key}"

        return None

    def _update_change_flags(
        self,
        change_flags: Dict[str, bool],
        fabric_type: str,
        fabric_name: str,
        role_path: str
    ) -> None:
        """Update the change detection flags JSON file."""
        flags_file = os.path.join(role_path, 'files', f"{fabric_name}_changes_detected_flags.json")

        # Read existing flags
        existing_flags = {}
        if os.path.exists(flags_file):
            try:
                with open(flags_file, 'r') as f:
                    existing_flags = json.load(f)
            except (json.JSONDecodeError, IOError):
                existing_flags = {}

        # Ensure structure exists
        if fabric_name not in existing_flags:
            existing_flags[fabric_name] = {}
        if fabric_type not in existing_flags[fabric_name]:
            existing_flags[fabric_name][fabric_type] = {}

        # Update flags that are True
        for flag_name, flag_value in change_flags.items():
            if flag_value:
                existing_flags[fabric_name][fabric_type][flag_name] = True

        # Update changes_detected_any if any flag is True
        if any(change_flags.values()):
            existing_flags[fabric_name][fabric_type]['changes_detected_any'] = True

        # Write updated flags
        os.makedirs(os.path.dirname(flags_file), exist_ok=True)
        with open(flags_file, 'w') as f:
            json.dump(existing_flags, f, indent=2)
