#!/usr/bin/env python3
"""Restore the morning-briefing-en schedule deleted by E2E test.

Recreates both:
  1. EventBridge Scheduler schedule in the openclaw-cron group
  2. DynamoDB CRON# record under USER#user_9dc5386ba1124fbd

Run once, then delete this script.
"""

import json

import boto3

REGION = "ap-southeast-2"
ACCOUNT = "657117630614"

# Original schedule details
USER_ID = "user_9dc5386ba1124fbd"
ACTOR_ID = "telegram:6087229962"
CHANNEL = "telegram"
CHANNEL_TARGET = "6087229962"
NAMESPACE = "telegram_6087229962"
SCHEDULE_ID = "c4ad1090"
SCHEDULE_NAME_FRIENDLY = "morning-briefing-en"
EB_SCHEDULE_NAME = f"openclaw-{NAMESPACE}-{SCHEDULE_ID}"
SCHEDULE_GROUP = "openclaw-cron"
EXPRESSION = "cron(30 7 * * ? *)"
TIMEZONE = "Australia/Sydney"
MESSAGE = "[task:morning-briefing-en] Morning Briefing EN"
CRON_LAMBDA_ARN = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:openclaw-cron-executor"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/openclaw-cron-scheduler-role"
IDENTITY_TABLE = "openclaw-identity"


def restore_eventbridge():
    scheduler = boto3.client("scheduler", region_name=REGION)
    target_input = json.dumps({
        "userId": USER_ID,
        "actorId": ACTOR_ID,
        "channel": CHANNEL,
        "channelTarget": CHANNEL_TARGET,
        "message": MESSAGE,
        "scheduleId": SCHEDULE_ID,
        "scheduleName": SCHEDULE_NAME_FRIENDLY,
    })
    try:
        scheduler.create_schedule(
            Name=EB_SCHEDULE_NAME,
            GroupName=SCHEDULE_GROUP,
            ScheduleExpression=EXPRESSION,
            ScheduleExpressionTimezone=TIMEZONE,
            FlexibleTimeWindow={"Mode": "OFF"},
            State="ENABLED",
            Target={
                "Arn": CRON_LAMBDA_ARN,
                "RoleArn": ROLE_ARN,
                "Input": target_input,
            },
            Description=f"OpenClaw cron: {SCHEDULE_NAME_FRIENDLY}",
        )
        print(f"EventBridge schedule created: {EB_SCHEDULE_NAME}")
    except scheduler.exceptions.ConflictException:
        print(f"EventBridge schedule already exists: {EB_SCHEDULE_NAME}")


def restore_dynamodb():
    dynamodb = boto3.resource("dynamodb", region_name=REGION)
    table = dynamodb.Table(IDENTITY_TABLE)
    table.put_item(Item={
        "PK": f"USER#{USER_ID}",
        "SK": f"CRON#{SCHEDULE_ID}",
        "scheduleId": SCHEDULE_ID,
        "scheduleName": SCHEDULE_NAME_FRIENDLY,
        "expression": EXPRESSION,
        "timezone": TIMEZONE,
        "message": MESSAGE,
        "channel": CHANNEL,
        "channelTarget": CHANNEL_TARGET,
        "actorId": ACTOR_ID,
        "enabled": True,
        "createdAt": "2026-03-10T00:00:00.000Z",
        "updatedAt": "2026-03-15T00:00:00.000Z",
    })
    print(f"DynamoDB CRON# record restored: USER#{USER_ID} / CRON#{SCHEDULE_ID}")


if __name__ == "__main__":
    restore_eventbridge()
    restore_dynamodb()
    print("Done. Delete this script after verifying.")
