import httpx
import pytest

from src.clients.notifier import MockSlack, SlackWebhook, build_notifier


def test_build_notifier_defaults_to_mock(monkeypatch):
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    notifier = build_notifier()
    assert isinstance(notifier, MockSlack)


def test_build_notifier_returns_webhook_when_env_set(monkeypatch):
    monkeypatch.setenv(
        "SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/FAKE/WEBHOOK/URL"
    )
    notifier = build_notifier()
    assert isinstance(notifier, SlackWebhook)
    assert notifier.webhook_url.endswith("/FAKE/WEBHOOK/URL")


def test_build_notifier_treats_blank_env_as_unset(monkeypatch):
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "   ")
    assert isinstance(build_notifier(), MockSlack)


def test_slack_webhook_posts_expected_payload(monkeypatch):
    captured: dict = {}

    def fake_post(url, json, timeout):
        captured["url"] = url
        captured["json"] = json
        captured["timeout"] = timeout
        return httpx.Response(200, request=httpx.Request("POST", url))

    monkeypatch.setattr(httpx, "post", fake_post)

    sw = SlackWebhook(webhook_url="https://hooks.slack.com/services/X/Y/Z")
    result = sw.send(
        channel="#soc-alerts", message="brute force contained", severity="high"
    )

    assert captured["url"] == "https://hooks.slack.com/services/X/Y/Z"
    assert "[HIGH]" in captured["json"]["text"]
    assert "#soc-alerts" in captured["json"]["text"]
    assert "brute force contained" in captured["json"]["text"]
    assert result["ok"] is True
    assert result["transport"] == "slack_webhook"
    assert len(sw.sent) == 1


def test_slack_webhook_raises_on_http_error(monkeypatch):
    def fake_post(url, json, timeout):
        return httpx.Response(500, request=httpx.Request("POST", url))

    monkeypatch.setattr(httpx, "post", fake_post)

    sw = SlackWebhook(webhook_url="https://hooks.slack.com/services/X/Y/Z")
    with pytest.raises(httpx.HTTPStatusError):
        sw.send(channel="#x", message="m", severity="low")
