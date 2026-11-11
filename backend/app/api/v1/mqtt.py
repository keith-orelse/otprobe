from fastapi import APIRouter, Depends, Path
from fastapi.responses import PlainTextResponse

from app import schemas
from app.api.deps import admin_only, any_user, get_ctx
from app.context import AppContext
from app.core.errors import ProblemError
from app.core.principal import CurrentUser
from app.services import mqtt_accounts

router = APIRouter(prefix="/mqtt", tags=["mqtt"])
Username = Path(pattern=schemas.MQTT_USERNAME, examples=["sensor01"])


@router.get("/broker", response_model=schemas.MqttBrokerStatus,
            summary="Bundled MQTT broker: running state, listeners and security checks (log: admins only)")
async def broker(user: CurrentUser = Depends(any_user), ctx: AppContext = Depends(get_ctx)):
    return mqtt_accounts.broker_status(ctx, admin=user.role == "ADMIN")


@router.get("/ca.pem", response_class=PlainTextResponse, dependencies=[Depends(any_user)],
            summary="CA certificate to install on devices so they trust the broker")
async def ca_pem(ctx: AppContext = Depends(get_ctx)):
    pem = mqtt_accounts.ca_pem(ctx)
    if not pem:
        raise ProblemError(404, "no-ca", "No CA certificate", "OTPROBE_TLS_CA_FILE is not set")
    return PlainTextResponse(pem, media_type="application/x-pem-file",
                             headers={"Content-Disposition": 'attachment; filename="otprobe-ca.pem"'})


@router.get("/accounts", response_model=list[schemas.MqttAccount], dependencies=[Depends(any_user)],
            summary="Device accounts, with who is connected now")
async def accounts(ctx: AppContext = Depends(get_ctx)):
    return mqtt_accounts.list_accounts(ctx)


@router.post("/accounts", response_model=schemas.MqttAccountSecret, status_code=201,
             summary="Create a device account (admin). The password is in this response only")
async def create(req: schemas.MqttAccountCreate, user: CurrentUser = Depends(admin_only),
                 ctx: AppContext = Depends(get_ctx)):
    return await mqtt_accounts.create_account(ctx, req, user.actor)


@router.patch("/accounts/{username}", response_model=schemas.MqttAccount,
              summary="Link to an asset, enable/disable, or describe an account (admin)")
async def update(req: schemas.MqttAccountUpdate, username: str = Username, user: CurrentUser = Depends(admin_only),
                 ctx: AppContext = Depends(get_ctx)):
    return await mqtt_accounts.update_account(ctx, username, req, user.actor)


@router.post("/accounts/{username}/password", response_model=schemas.MqttAccountSecret,
             summary="New password (admin). The device is disconnected; the password is in this response only")
async def new_password(username: str = Username, user: CurrentUser = Depends(admin_only),
                       ctx: AppContext = Depends(get_ctx)):
    return await mqtt_accounts.new_password(ctx, username, user.actor)


@router.delete("/accounts/{username}", status_code=204, summary="Delete an account (admin); the device is disconnected")
async def delete(username: str = Username, user: CurrentUser = Depends(admin_only),
                 ctx: AppContext = Depends(get_ctx)):
    await mqtt_accounts.delete_account(ctx, username, user.actor)
