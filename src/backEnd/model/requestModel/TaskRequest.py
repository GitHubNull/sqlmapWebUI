from pydantic import BaseModel, Field
from typing import Annotated, Optional


# class TaskAddRequest(BaseModel):
#     # taskid: Annotated[Optional[str], Field(description="任务ID，可选参数")]
#     options: Annotated[dict, Field(min_length=1, description="参数列表")]


class TaskDeleteRequest(BaseModel):
    taskid: str = Field("", min_length=16, max_length=16, description='任务ID')


class TaskStopRequest(BaseModel):
    taskid: str = Field("", min_length=16, max_length=16, description='任务ID')


class TaskUpdateRequest(BaseModel):
    taskid: str = Field("", min_length=16, max_length=16, description='任务ID')
    options: Annotated[dict, Field(min_length=1)]


class TaskListRequest(BaseModel):
    pass


class TaskQueryRequest(BaseModel):
    taskid: str = Field("", min_length=16, max_length=16, description='任务ID')


class TaskAddRequest(BaseModel):
    scanUrl: Annotated[str, Field(description="扫描地址...")]
    host: Annotated[str, Field(description="扫描域名...")]
    method: Annotated[str, Field(description="请求方法...")]
    headers: Annotated[list, Field(description="请求头...")]
    body: Annotated[str, Field(description="请求体...")]
    options: Annotated[dict, Field(description="扫描参数...")]


class TaskFindByUrlPathRequest(BaseModel):
    urlPath: Annotated[str, Field(description="urlPath...")]


class TaskFindByBodyKeyWordRequest(BaseModel):
    bodyKeyWord: Annotated[str, Field(description="bodyKeyWord...")]


class TaskFindByHeaderKeyWordRequest(BaseModel):
    headerKeyWord: Annotated[str, Field(description="headerKeyWord...")]


class TaskLogQueryRequest(BaseModel):
    taskId: str = Field("", min_length=3, max_length=64, description='任务ID')


class TaskQueryRequest(BaseModel):
    taskId: str = Field("", min_length=3, max_length=64, description='任务ID')
