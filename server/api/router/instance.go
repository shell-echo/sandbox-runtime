package router

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/shell-echo/sandbox-runtime/instance"
	"github.com/shell-echo/sandbox-runtime/internal"
	"github.com/shell-echo/sandbox-runtime/server/api/gonic"
)

type instanceHandler struct {
	service instance.Service
}

type createInstanceRequest struct {
	Name     string                `json:"name"`
	Workload instance.WorkloadType `json:"workload"`
}

func (h instanceHandler) create(c *gonic.Context) {
	var request createInstanceRequest
	if err := decodeJSON(c, &request); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			c.Resp(internal.ErrPayloadTooLarge.New())
			return
		}
		c.Resp(internal.ErrInstanceInvalidSpec.Wrap(err))
		return
	}
	spec := instance.Spec{Name: request.Name, Workload: request.Workload}
	inst, err := h.service.Create(c.Request.Context(), spec)
	c.Resp(instanceResult(inst, err))
}

func (h instanceHandler) list(c *gonic.Context) {
	instances, err := h.service.List(c.Request.Context())
	if err != nil {
		c.Resp(mapInstanceError(err))
		return
	}
	c.Resp(instances)
}

func (h instanceHandler) inspect(c *gonic.Context) {
	inst, err := h.service.Inspect(c.Request.Context(), c.Param("id"))
	c.Resp(instanceResult(inst, err))
}

func (h instanceHandler) start(c *gonic.Context) {
	inst, err := h.service.Start(c.Request.Context(), c.Param("id"))
	c.Resp(instanceResult(inst, err))
}

func (h instanceHandler) stop(c *gonic.Context) {
	inst, err := h.service.Stop(c.Request.Context(), c.Param("id"))
	c.Resp(instanceResult(inst, err))
}

func (h instanceHandler) remove(c *gonic.Context) {
	id := c.Param("id")
	if err := h.service.Remove(c.Request.Context(), id); err != nil {
		c.Resp(mapInstanceError(err))
		return
	}
	c.Resp(map[string]string{"id": id})
}

func instanceResult(inst *instance.Instance, err error) any {
	if err != nil {
		return mapInstanceError(err)
	}
	return inst
}

func mapInstanceError(err error) error {
	switch {
	case errors.Is(err, instance.ErrInvalidSpec):
		return internal.ErrInstanceInvalidSpec.Wrap(err)
	case errors.Is(err, instance.ErrNotFound):
		return internal.ErrInstanceNotFound.Wrap(err)
	case errors.Is(err, instance.ErrAlreadyExists):
		return internal.ErrInstanceAlreadyExists.Wrap(err)
	case errors.Is(err, instance.ErrInvalidTransition):
		return internal.ErrInstanceInvalidState.Wrap(err)
	case errors.Is(err, instance.ErrLimitExceeded):
		return internal.ErrInstanceLimitExceeded.Wrap(err)
	default:
		return internal.ErrSystem.Wrap(err)
	}
}

func decodeJSON(c *gonic.Context, dst any) error {
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("request body must contain a single JSON value")
		}
		return err
	}
	return nil
}
