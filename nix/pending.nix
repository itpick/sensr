# What the VM tests cannot assert yet because the crate behind it has not
# landed. Each flag is true while that part is pending; the tests then check
# only what exists today (and report the part as PENDING in their log).
#
# When a crate lands, set its flag to false in the same PR, so the tests
# start asserting it and CI proves it works. Never set one back to true to
# make CI pass; fix the code instead.
{
  # sensr-agent stays running as a daemon and serves its IPC socket
  # (/run/sensr/agent.sock). Until then the stub binary runs and exits 0.
  agentDaemon = true;

  # `sensr config get / --json` answers over IPC (T-0401; sensr-cli +
  # sensr-ipc + sensr-config).
  configGet = true;

  # sensr-api stays running and answers HTTP on the management address.
  apiDaemon = true;

  # The agent imports an OPNsense config.xml from the seed folder
  # (sensr-import-opnsense) and applies it (sensr-apply, sensr-net,
  # sensr-rules, sensr-services). Gates every slice assertion that needs the
  # router to be configured by sensr.
  importApply = true;

  # `sensr config set` + `sensr apply --confirm-within`: an unconfirmed apply
  # rolls back on its own (sensr-apply confirm timer).
  commitConfirm = true;
}
