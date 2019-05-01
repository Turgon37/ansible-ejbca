
from ansible.plugins.action import ActionBase
from ansible.plugins.action.normal import ActionModule as ActionNormal

import os


class EJBCAActionModule(ActionBase):

    TRANSFERS_FILES = True

    def _ensure_invocation(self, result):
        # NOTE: adding invocation arguments here needs to be kept in sync with
        # any no_log specified in the argument_spec in the module.
        # This is not automatic.
        if 'invocation' not in result:
            if self._play_context.no_log:
                result['invocation'] = "CENSORED: no_log is set"
            else:
                result["invocation"] = self._task.args.copy()

        if isinstance(result['invocation'], dict) and 'content' in result['invocation']:
            result['invocation']['content'] = 'CENSORED: content is a no_log parameter'

        return result

    def _check_local_file_readability(self, path):
        if not os.path.isfile(path):
            raise Exception('file {} does not exist'.format(path))
        if not os.access(path, os.R_OK):
            raise Exception('file {} is not readable'.format(path))

    def run(self, tmp=None, task_vars=None):
        """"""

        result = super(EJBCAActionModule, self).run(tmp, task_vars)
        del tmp # tmp no longer has any effect

        client_cert = self._task.args.get('client_cert', None)
        client_key = self._task.args.get('client_key', None)
        if client_key and not client_cert:
            result['failed'] = True
            result['msg'] = 'you cannot set client_key without client_cert'
            return self._ensure_invocation(result)
        publickey_path = None
        if self._task.args.get('remote_publickey_path', True) is False:
            publickey_path = self._task.args.get('publickey_path', None)

        # check local files
        try:
            for f in [client_cert, client_key, publickey_path]:
                if not f:
                    continue
                self._check_local_file_readability(f)
        except Exception as ex:
            result['failed'] = True
            result['msg'] = str(ex)
            return self._ensure_invocation(result)

        module_args = self._task.args.copy()
        additionnal_remote_files = []
        for var_f in ['client_cert', 'client_key', 'publickey_path']:
            var = locals()[var_f]
            if not var:
                continue
            module_args[var_f] = self._connection._shell.join_path(
                self._connection._shell.tmpdir,
                os.path.basename(var))
            self._transfer_file(var, module_args[var_f])
            additionnal_remote_files.append(module_args[var_f])

        # ensure permission for additionnal files
        if additionnal_remote_files:
            self._fixup_perms2(additionnal_remote_files, execute=False)

        result = self._execute_module(module_args=module_args, task_vars=task_vars)

        # Delete tmp path
        self._remove_tmp_path(self._connection._shell.tmpdir)

        return result
