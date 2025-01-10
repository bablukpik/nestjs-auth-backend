import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Types } from 'mongoose';

@Schema()
export class User {
  @Prop()
  _id?: Types.ObjectId; // Marked optional since Mongoose auto-generates it. We can omit this field too

  @Prop({ unique: true })
  email: string;

  @Prop()
  refreshToken?: string;

  @Prop()
  password: string;
}

export const UserSchema = SchemaFactory.createForClass(User);

// Mongoose will automatically handle the _id field.
