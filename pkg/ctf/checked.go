package ctf

import (
	"context"
	"fmt"
)

// Checked wraps a driver so every result is validated against the contract.
// A violation is a remote error naming the operation, so a driver bug never
// reaches a consumer as data with an undefined meaning.
func Checked(name string, d Driver) Driver { return &checked{Driver: d, name: name} }

type checked struct {
	Driver
	name string
}

// Unwrap returns the wrapped driver.
func (c *checked) Unwrap() Driver { return c.Driver }

// Err passes on the wrapped driver's handshake error, if it has one.
func (c *checked) Err() error {
	if h, ok := c.Driver.(interface{ Err() error }); ok {
		return h.Err()
	}
	return nil
}

func (c *checked) bad(op string, err error) error {
	if err == nil {
		return nil
	}
	return Errorf(KindRemote, "driver %s %s broke the protocol: %v", c.name, op, err)
}

func (c *checked) ListChallenges(ctx context.Context) ([]Challenge, error) {
	out, err := c.Driver.ListChallenges(ctx)
	if err != nil {
		return nil, err
	}
	for i := range out {
		if err := ValidateChallenge(&out[i]); err != nil {
			return nil, c.bad("list_challenges", err)
		}
	}
	return out, nil
}

func (c *checked) GetChallenge(ctx context.Context, id string) (*Challenge, error) {
	out, err := c.Driver.GetChallenge(ctx, id)
	if err != nil {
		return nil, err
	}
	return out, c.bad("get_challenge", ValidateChallenge(out))
}

func (c *checked) Submit(ctx context.Context, id, flag string) (*SubmitResult, error) {
	out, err := c.Driver.Submit(ctx, id, flag)
	if err != nil {
		return nil, err
	}
	return out, c.bad("submit", ValidateSubmit(out))
}

func (c *checked) Instance(ctx context.Context, action, challenge string) (*Instance, error) {
	out, err := c.Driver.Instance(ctx, action, challenge)
	if err != nil {
		return nil, err
	}
	if out != nil && out.Action == "" {
		out.Action = action
	}
	return out, c.bad("instance "+action, ValidateInstance(out))
}

func (c *checked) Hints(ctx context.Context, challengeID string) ([]Hint, error) {
	out, err := c.Driver.Hints(ctx, challengeID)
	if err != nil {
		return nil, err
	}
	for _, h := range out {
		if h.ID == "" {
			return nil, c.bad("hints", fmt.Errorf("hint without id"))
		}
	}
	return out, nil
}
