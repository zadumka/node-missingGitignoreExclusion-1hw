import { Joi, Segments } from 'celebrate';

export const registerUserSchema = {
  [Segments.BODY]: {
    email: Joi.string().email().required(),
    password: Joi.string().min(8).required(),
  },
};

export const loginUserSchema = {
  [Segments.BODY]: {
    email: Joi.string().email().required(),
    password: Joi.string().required(),
  },
};
