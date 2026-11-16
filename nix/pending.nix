# What the VM tests cannot assert yet because the crate behind it has not
# landed. Each flag is true while that part is pending; the tests then check
# only what exists today (and report the part as PENDING in their log).
#
# When a crate lands, set its flag to false in the same PR, so the tests
# start asserting it and CI proves it works. Never set one back to true to
# make CI pass; fix the code instead.
{
  # sensr-agent stays running as a daemon and serves its IPC socket
  # (/run/sensr/agent.sock). Landed with the agent skeleton (PR #12).
  agentDaemon = false;

  # `sensr config get --json` answers over IPC (T-0401). Landed with the
  # CLI and agent store.
  configGet = false;

  # sensr-api stays running and answers HTTP on the management address.
  apiDaemon = false;

  # The agent imports an OPNsense config.xml from the seed folder
  # (sensr-import-opnsense) and applies it (sensr-apply, sensr-net,
  # sensr-rules, sensr-services). Gates every slice assertion that needs the
  # router to be configured by sensr.
  #
  # Open (found by checks.slice with importApply = false): the boot apply
  # of the imported home-router.xml is rejected because the Kea check
  # (`kea-dhcp4 -t` in /run/sensr/.check) runs before the VLAN devices it
  # names (vlan01, vlan02) exist; they are created by the same apply.
  importApply = true;

  # `sensr config set` + `sensr config commit --confirm SECS`: an
  # unconfirmed commit rolls back on its own (agent confirm timer). Landed.
  commitConfirm = false;
}
