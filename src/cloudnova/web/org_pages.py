"""HTML for the organization settings page.

Kept out of ``app.py`` so the routes there stay readable. Pure functions of
data in, markup out - no Supabase calls, which is also what makes them cheap
to test.

The controls here are hidden according to the caller's role, but that is
presentation only. Every one of them posts to a route that goes through RLS,
so hiding a button never decides anything: it only avoids offering an action
the database would refuse.
"""

from __future__ import annotations

import html

from cloudnova.platform.billing import Entitlements
from cloudnova.platform.tenancy import Invitation, Member, Org

_ROLES = ("owner", "admin", "member", "viewer")

_ROLE_HELP = {
    "owner": "Full control, including roles and deleting the organization.",
    "admin": "Can invite and remove people, and manage targets and scans.",
    "member": "Can run and save scans.",
    "viewer": "Read-only.",
}


def _e(v: object) -> str:
    return html.escape(str(v), quote=True)


def _role_badge(role: str) -> str:
    return f'<span class="rolechip {_e(role)}">{_e(role)}</span>'


def _member_row(member: Member, *, current: Org, me: str, can_manage: bool) -> str:
    is_self = member.user_id == me
    name = member.full_name or member.email or member.user_id
    who = f"<b>{_e(name)}</b>"
    if member.full_name and member.email:
        who += f"<br><span class='muted'>{_e(member.email)}</span>"
    if is_self:
        who += " <span class='muted'>· you</span>"

    # An owner may change roles. Never your own: the only way that helps is
    # demoting yourself out of the last owner seat.
    if can_manage and current.role == "owner" and not is_self:
        options = "".join(
            f'<option value="{_e(r)}"{" selected" if r == member.role else ""}>{_e(r)}</option>'
            for r in _ROLES
        )
        role_cell = (
            "<form method='post' action='/org/member/role' style='margin:0'>"
            f"<input type='hidden' name='user_id' value='{_e(member.user_id)}'>"
            f"<select name='role' class='orgpick' onchange='this.form.submit()'>{options}</select>"
            "<noscript><button class='linkish' type='submit'>Save</button></noscript>"
            "</form>"
        )
    else:
        role_cell = _role_badge(member.role)

    if can_manage and not is_self:
        remove = (
            "<form method='post' action='/org/member/remove' style='margin:0'>"
            f"<input type='hidden' name='user_id' value='{_e(member.user_id)}'>"
            "<button class='linkish danger' type='submit'>Remove</button></form>"
        )
    else:
        remove = ""

    return (
        f"<tr><td>{who}</td><td>{role_cell}</td>"
        f"<td class='muted'>{_e(member.joined_at[:10])}</td><td>{remove}</td></tr>"
    )


def _invite_row(invite: Invitation, *, can_manage: bool) -> str:
    revoke = ""
    if can_manage:
        revoke = (
            "<form method='post' action='/org/invite/revoke' style='margin:0'>"
            f"<input type='hidden' name='invitation_id' value='{_e(invite.id)}'>"
            "<button class='linkish danger' type='submit'>Revoke</button></form>"
        )
    return (
        f"<tr><td>{_e(invite.email)}</td><td>{_role_badge(invite.role)}</td>"
        f"<td class='muted'>expires {_e(invite.expires_at[:10])}</td><td>{revoke}</td></tr>"
    )


def _invite_form(current: Org) -> str:
    options = "".join(
        f'<option value="{_e(r)}"{" selected" if r == "member" else ""}>'
        f"{_e(r)} - {_e(_ROLE_HELP[r])}</option>"
        for r in _ROLES
    )
    return f"""
    <div class="card" style="margin-top:16px">
      <h3 style="margin-top:0">Invite someone to {_e(current.name)}</h3>
      <form method="post" action="/org/invite">
        <label for="invite-email">Email</label>
        <input id="invite-email" type="email" name="email" required
               placeholder="colleague@company.com">
        <label for="invite-role">Role</label>
        <select id="invite-role" name="role" class="orgpick"
                style="width:100%;padding:12px 14px">{options}</select>
        <p style="margin-top:16px"><button class="btn" type="submit">Send invitation</button></p>
      </form>
      <p class="muted" style="margin:0">They will see the invitation the next time they
        sign in with that address. Invitations expire after 14 days.</p>
    </div>"""


def _limit(used: int, allowed: int | None) -> str:
    """`3 / 10`, or `3 / unlimited`. Never a bare number - a usage figure with
    nothing to compare it against tells the reader nothing."""
    return f"{used} / {'unlimited' if allowed is None else allowed}"


def _plan_panel(allowance: Entitlements | None) -> str:
    if allowance is None:
        return ""
    if allowance.degraded:
        # Say the numbers are unavailable rather than showing zeros, which
        # would read as "you have used nothing", the opposite of the truth.
        return (
            '<div class="card" style="margin-top:16px">'
            '<h3 style="margin-top:0">Plan</h3>'
            f'<p class="notice">Billing information is unavailable right now, so '
            f"limits are not being applied. {_e(allowance.error)}</p></div>"
        )

    seats = _limit(allowance.seats_used, allowance.plan.max_seats)
    scans = _limit(allowance.usage.scans_this_month, allowance.plan.max_scans_per_month)
    # An org can sit above its limit after a downgrade, or because seats were
    # filled before a plan changed. The limit stops the next invite either way,
    # so say so here rather than letting the numbers look merely odd.
    over = allowance.plan.max_seats is not None and allowance.seats_used > allowance.plan.max_seats
    overage = (
        '<p class="notice" style="margin:10px 0 0">This organization is using '
        f"{allowance.seats_used} of {allowance.plan.max_seats} seats. Nobody loses access, "
        "but you cannot invite anyone else until a seat frees up or the plan changes.</p>"
        if over
        else ""
    )
    pending = (
        f'<p class="muted" style="margin:6px 0 0">Includes '
        f"{allowance.usage.pending_invites} pending invitation(s), which hold a seat "
        "until accepted or revoked.</p>"
        if allowance.usage.pending_invites
        else ""
    )
    lapsed = (
        f'<p class="notice" style="margin:10px 0 0">Subscription status: '
        f"{_e(allowance.status)}. The organization is on the free limits.</p>"
        if allowance.status in ("canceled", "incomplete")
        else ""
    )
    return f"""
    <div class="card" style="margin-top:16px">
      <div style="display:flex;justify-content:space-between;align-items:baseline;gap:16px">
        <h3 style="margin:0">Plan</h3>
        <span class="rolechip owner">{_e(allowance.plan.name)}</span>
      </div>
      <table style="margin-top:10px">
        <tbody>
          <tr><td>Seats</td><td><b>{_e(seats)}</b></td></tr>
          <tr><td>Scans this month</td><td><b>{_e(scans)}</b></td></tr>
        </tbody>
      </table>
      {pending}
      {overage}
      {lapsed}
    </div>"""


def org_settings_body(
    *,
    current: Org,
    members: list[Member],
    invites: list[Invitation],
    me: str,
    allowance: Entitlements | None = None,
    notice: str = "",
    error: str = "",
) -> str:
    """The settings page: who is in the org, who has been invited, and roles."""
    can_manage = current.role in ("owner", "admin")

    banner = ""
    if error:
        banner = f'<p class="notice">{_e(error)}</p>'
    elif notice:
        banner = f'<p class="notice ok">{_e(notice)}</p>'

    member_rows = (
        "".join(_member_row(m, current=current, me=me, can_manage=can_manage) for m in members)
        or '<tr><td colspan="4" class="muted">No members.</td></tr>'
    )

    invites_block = ""
    if invites:
        rows = "".join(_invite_row(i, can_manage=can_manage) for i in invites)
        invites_block = f"""
        <div class="card" style="margin-top:16px">
          <h3 style="margin-top:0">Pending invitations</h3>
          <table><thead><tr><th>Email</th><th>Role</th><th></th><th></th></tr></thead>
          <tbody>{rows}</tbody></table>
        </div>"""

    invite_block = (
        _invite_form(current)
        if can_manage
        else (
            '<p class="muted" style="margin-top:16px">Only owners and admins can invite people.</p>'
        )
    )

    return f"""
    <div class="kicker">{_e(current.name)}</div>
    <h1 style="margin:4px 0">Organization settings</h1>
    <p class="muted" style="margin-top:0">You are {_role_badge(current.role)} here.</p>
    {banner}
    <div class="card" style="margin-top:14px">
      <h3 style="margin-top:0">Members</h3>
      <table><thead><tr><th>Person</th><th>Role</th><th>Joined</th><th></th></tr></thead>
      <tbody>{member_rows}</tbody></table>
    </div>
    {_plan_panel(allowance)}
    {invites_block}
    {invite_block}
    {_create_org_form()}"""


def _create_org_form() -> str:
    return """
    <div class="card" style="margin-top:16px">
      <h3 style="margin-top:0">New organization</h3>
      <form method="post" action="/orgs/create">
        <label for="org-name">Name</label>
        <input id="org-name" type="text" name="name" required placeholder="Acme Security">
        <p style="margin-top:16px">
          <button class="btn ghost" type="submit">Create organization</button></p>
      </form>
      <p class="muted" style="margin:0">You become its owner. Scans are saved against
        whichever organization is selected in the header.</p>
    </div>"""


def invitations_body(invites: list[dict[str, object]], *, notice: str = "", error: str = "") -> str:
    """Invitations addressed to the signed-in user."""
    banner = ""
    if error:
        banner = f'<p class="notice">{_e(error)}</p>'
    elif notice:
        banner = f'<p class="notice ok">{_e(notice)}</p>'

    if not invites:
        body = '<p class="muted">No pending invitations.</p>'
    else:
        cards = []
        for invite in invites:
            org = invite.get("organizations")
            org_name = org.get("name") if isinstance(org, dict) else None
            cards.append(
                f"""
            <div class="card" style="margin-top:12px">
              <div style="display:flex;justify-content:space-between;align-items:center;gap:16px">
                <div>
                  <b>{_e(org_name or "An organization")}</b><br>
                  <span class="muted">invited as {_e(invite.get("role", "member"))} ·
                    expires {_e(str(invite.get("expires_at", ""))[:10])}</span>
                </div>
                <form method="post" action="/invites/accept" style="margin:0">
                  <input type="hidden" name="invitation_id" value="{_e(invite.get("id", ""))}">
                  <button class="btn" type="submit">Accept</button>
                </form>
              </div>
            </div>"""
            )
        body = "".join(cards)

    return f"""
    <div class="kicker">Invitations</div>
    <h1 style="margin:4px 0">You have been invited</h1>
    <p class="muted" style="margin-top:0">Invitations sent to your email address.</p>
    {banner}
    {body}"""
